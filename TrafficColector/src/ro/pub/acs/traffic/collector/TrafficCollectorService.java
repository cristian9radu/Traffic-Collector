/**
 * Class for the Collector Foreground Service.
 * @author Fratila Catalin Ionut
 */

package ro.pub.acs.traffic.collector;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;

import ro.pub.acs.traffic.utils.CryptTool;
import ro.pub.acs.traffic.utils.Database;
import ro.pub.acs.traffic.utils.Results;
import ro.pub.acs.traffic.utils.Utils;

import android.app.Notification;
import android.app.PendingIntent;
import android.app.Service;
import android.content.Context;
import android.content.Intent;
import android.location.GpsStatus;
import android.location.Location;
import android.location.LocationListener;
import android.location.LocationManager;
import android.os.Binder;
import android.os.Bundle;
import android.os.Environment;
import android.os.IBinder;
import android.os.SystemClock;
import android.util.Base64;
import android.util.Log;

public class TrafficCollectorService extends Service 
{

	private static TrafficCollectorService instance = null;

	/** Tag used for debug information */
	private static String TAG = "DEBUG_INFO";
	private File file;
	private BufferedWriter collector;
	
	private LocationManager locationManager;
	private LocationListener locationListener, WiFiLocationListener;
	private GpsStatus.Listener statusListener;
	
	private Location mLastLocation;
	
	private long mLastLocationMillis;
	private long mUpdateMillis = 0;
	
	private boolean isGPSFix;
	
	private float lastSpeed = -1;
	private double currentLat = 0, currentLong = 0;
	private double lastLat = 0, lastLong = 0;
	private long currentTimestamp = 0;
	private double currentAccuracy;
	
	private String id;
	
	private boolean real = false;
	
	private Database db;
	private Database db_statistics;
	private Database db_user;
	
	private Socket socket;
	private PrintWriter out;
	private BufferedReader in;
	
	private final IBinder mBinder = new MyBinder();

	public static boolean isInstanceCreated() { 
		return instance != null; 
	}
	
	// Handler that receives messages from the thread
	public void onCreate() {
		super.onCreate();
		/* Notify that the service started */
	    showNotification(); 
		/*
		 * GPS stuff
		 */
	    db = new Database(this, "collector", "routes", new String[] { "lat", "long", "speed", "timestamp" });
	    db_statistics = new Database(this, "collector", "statistics", new String[] { "speed", "max_speed", "avg_speed", "length", "no", "uuid" });
		
	    locationManager = (LocationManager) this.getSystemService(Context.LOCATION_SERVICE);
	    /*Criteria criteria = new Criteria();
	    criteria.setAccuracy(Criteria.ACCURACY_FINE); 
	    criteria.setPowerRequirement(Criteria.NO_REQUIREMENT);
	    locationManager.getBestProvider(criteria, true);*/
		locationListener = new LocationListener() {
			public void onLocationChanged(Location location) {
				if (location == null) return;

			    mLastLocationMillis = SystemClock.elapsedRealtime();

			    makeUseOfNewLocation(location);

			    mLastLocation = location;
			    
				
			}

			public void onStatusChanged(String provider, int status, Bundle extras) {}

			public void onProviderEnabled(String provider) {}

			public void onProviderDisabled(String provider) {}
		};
		
		WiFiLocationListener = new LocationListener() {
			public void onLocationChanged(Location location) {
				if (mLastLocation != null)
					isGPSFix = (SystemClock.elapsedRealtime() - mLastLocationMillis) < 3000;
				if(real && !isGPSFix) {
					long times = System.currentTimeMillis();
            		if (location != null && out != null) {
            			out.println(location.getLatitude() + " " + location.getLongitude() + " " + (-2) + " " + times);
            		}
				}
			}

			public void onStatusChanged(String provider, int status, Bundle extras) {}

			public void onProviderEnabled(String provider) {}

			public void onProviderDisabled(String provider) {}
		};
		
		statusListener = new GpsStatus.Listener() {
		    public void onGpsStatusChanged(int event) {
		        switch (event) {
		            case GpsStatus.GPS_EVENT_SATELLITE_STATUS:
		                if (mLastLocation != null)
		                    isGPSFix = (SystemClock.elapsedRealtime() - mLastLocationMillis) < 3000;

		                if (isGPSFix) { // A fix has been acquired.
		                	
		                } else { // The fix has been lost.
		                	
		                }

		                break;
		            case GpsStatus.GPS_EVENT_FIRST_FIX:
		                // Do something.
		                isGPSFix = true;
		                break;
		        }
		    }
		};
		
		locationManager.addGpsStatusListener(statusListener);
		locationManager.requestLocationUpdates(LocationManager.GPS_PROVIDER, 100, 0, locationListener);
		locationManager.requestLocationUpdates(LocationManager.NETWORK_PROVIDER, 1000, 0, WiFiLocationListener);
		
		/*
		 * Storage file & database
		 */
		if(Utils.testCard())
		{
			File sdCard = Environment.getExternalStorageDirectory();
			File dir = new File (sdCard.getAbsolutePath() + "/trafficCollector/");
			dir.mkdirs();
			
			file = new File(dir, "journey.txt");
			FileWriter fw;
			try {
				fw = new FileWriter(file, true);
				collector = new BufferedWriter(fw);
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
		instance = this;
	}
	
	// We return the binder class upon a call of bindService
	@Override
	public IBinder onBind(Intent arg0) {
		return mBinder;
	}

	public class MyBinder extends Binder {
		TrafficCollectorService getService() {
			return TrafficCollectorService.this;
		}
	}
	
	public Results getCurrent() {
		Results res = new Results(lastSpeed, currentLong, currentLat, currentTimestamp);
		res.accuracy = currentAccuracy;
		return res;
	}
	
	@Override
    public int onStartCommand(Intent intent, int flags, int startId) {
		super.onStart(intent, startId);
		
		String facebook, twitter;
		
		db_user = new Database(this, "collector", "user", new String[] { "name", "username", "password", "uuid" });
		  
		Bundle bundle = intent.getExtras();
		real = bundle.getBoolean("realTime", false);
		id = bundle.getString("uuid");
		facebook = bundle.getString("facebook");
		twitter = bundle.getString("twitter");
		id = db_statistics.get("uuid");
		
		if(real)
		{
			try {
				String reply = "";
				socket = new Socket(Constants.Config.SERVER_SOCKET_NAME, Constants.Config.SERVER_SOCKET_PORT);
				out = new PrintWriter(socket.getOutputStream(), true);
                in = new BufferedReader(new InputStreamReader(
                		socket.getInputStream()));
                while (!reply.equals("ACK")) {
                    // send first message.
                	CryptTool ct = new CryptTool();
                	String lname = db_user.isEmpty() ? "0" : db_user.get("name").equals("") ? "0" : CryptTool.bytes2String(Base64.decode(db_user.get("name"), Base64.NO_WRAP));
                	String lusername = db_user.isEmpty() ? "0" : db_user.get("username").equals("") ? "0" : db_user.get("username");
                	String lpassword = db_user.isEmpty() ? "0" : db_user.get("password").equals("") ? "0" : ct.encrypt(db_user.get("password"));
                	
                	out.println("#s#" + lname + "#" + (facebook.equals("") ? "0" : facebook) + "#" + (twitter.equals("") ? "0" : twitter) + "#" + id + "#" + lusername + "#" + lpassword + "#" + ct.encrypt(db_user.get("uuid")));
                    
                	//socket_writer.println("#s#" + CryptTool.bytes2String(Base64.decode(db_user.get("name"), Base64.NO_WRAP)) + "#" + (facebook.equals("") ? "0" : facebook) + "#" + (twitter.equals("") ? "0" : twitter) + "#" + id + "#" + db_user.get("username") + "#" + ct.encrypt(db_user.get("password")) + "#" + ct.encrypt(db_user.get("uuid")));
                    
                    // wait for reply.
                    reply = in.readLine();
                }
			} catch (Exception e) {
				e.printStackTrace();
			}
		}
		
		return START_STICKY;
    }
	
	public void makeUseOfNewLocation(Location loc)
	{
		try {
			currentLat = loc.getLatitude();
			currentLong = loc.getLongitude();
			currentAccuracy = loc.getAccuracy();
			/*if(real) {
				Geocoder geoCoder = new Geocoder(this, Locale.getDefault());
			
				List<Address> addresses = geoCoder.getFromLocation(currentLat, currentLong, 1);

				currentLat = addresses.get(0).getLatitude();
				currentLong =  addresses.get(0).getLongitude();
			}*/
			 
			if(db_statistics.isEmpty())
				db_statistics.insert(new String[] { "-1", "-1", "-1", "-1", "-1", "-1"});
			float currentSpeed = loc.getSpeed();
			
			if(isGPSFix)
				db_statistics.update(new String[] {"speed"}, new String[] {currentSpeed + ""});
			else
				db_statistics.update(new String[] {"speed"}, new String[] {"0"});
			
			if(lastSpeed == -1 || 
					(lastSpeed == 0 && currentSpeed != 0) || 
					(lastSpeed != 0 && currentSpeed != 0) || 
					(lastSpeed !=0 && currentSpeed == 0))
			{
				String sno = db_statistics.get("no");
				db_statistics.update(new String[] { "no" }, new String[] { (Integer.parseInt(sno) + 1) + "" });
				
				String dataSpeed = db_statistics.get("max_speed");
				if(currentSpeed > Float.parseFloat(dataSpeed))
					db_statistics.update(new String[] { "max_speed", "no" }, new String[] { currentSpeed + "", (Integer.parseInt(sno) + 1) + "" });
				
				currentTimestamp = loc.getTime();
				
				if(Utils.testCard())
				{
					collector.write(currentLat + " " + currentLong + " " + currentSpeed + " " + currentTimestamp);
		        	collector.newLine();
				}
				if(real)
				{
					if(mUpdateMillis == 0 || (SystemClock.elapsedRealtime() - mUpdateMillis > 10000))
					{
						out.println(currentLat + " " + currentLong + " " + currentSpeed + " " + currentTimestamp);
						mUpdateMillis = SystemClock.elapsedRealtime();
					}
				}
	        	db.insert(new String[] { currentLat + "", currentLong + "", currentSpeed + "", currentTimestamp + "" });
	        	if(lastLat != 0)
	        	{
		        	double dim = (double) Utils.gps2m(lastLat, lastLong, currentLat, currentLong);
	        		//double dim = (float) Utils.distance_haversine(lastLat, lastLong, currentLat, currentLong);
					if(dim > 0.01)
					{
						String sdim = db_statistics.get("length");
						dim = ((double)Math.round(dim * 10000))/10000;
						if(sdim.equals("-1"))
							sdim = "0.0";
						db_statistics.update(new String[] { "length" }, new String[] { (Double.parseDouble(sdim) + dim) + "" });
					}
	        	}
	        	
				lastSpeed = currentSpeed;
	        	lastLat = currentLat;
	        	lastLong = currentLong;
			}
			
	    } catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	/**
	 * Method executed when the service is stopped
	 */
	@Override
	public void onDestroy() 
	{
		super.onDestroy();
		instance = null;
		db.close();
		db_user.close();
		db_statistics.close();
		
		if(Utils.testCard() && collector != null) {
			try {
				collector.close();
			} catch (IOException e) {
				e.printStackTrace();
			}
			if(file != null && file.length() == 0)
					file.delete();
		}
		if(locationManager != null && locationListener != null)
			locationManager.removeUpdates(locationListener);
		if(real) {
			if(out != null)
				out.println("#f#");
			if(socket != null) {
				try {
					socket.close();
					in.close();
					out.close();
				} catch (IOException e) {
					e.printStackTrace();
				}
			}
		}
		/* Hide notification */
		hideNotification();
		/* Stop all threads */
		Log.d(TAG, "CommunicationService destroyed");
	}
	
	/**
	 * Method that shows the notification that the service started
	 */
	private void showNotification()
	{
		//NotificationManager lNM = (NotificationManager) getSystemService(Context.NOTIFICATION_SERVICE);
	    int lIcon = R.drawable.icon2;
	    CharSequence lTickerText = "Traffic Collector Service Running";
	    long lWhen = System.currentTimeMillis();
	
	    Notification lNotification = new Notification(lIcon, lTickerText, lWhen);
	    
	    Context lContext = getApplicationContext();
	    CharSequence lContentTitle = "Traffic Collector";
	    CharSequence lContentText = "Traffic Collector Service Running!";
	    Intent lNotificationIntent = new Intent(this, TrafficCollectorService.class);
	    PendingIntent lContentIntent = PendingIntent.getActivity(this, 0, lNotificationIntent, 0);
	
	    lNotification.setLatestEventInfo(lContext, lContentTitle, lContentText, lContentIntent);
	    
	    startForeground(Notification.FLAG_ONGOING_EVENT, lNotification);
	}
	
	/**
	 * Hide notification
	 */
	private void hideNotification()
	{
		stopForeground(true);
	}
	
}