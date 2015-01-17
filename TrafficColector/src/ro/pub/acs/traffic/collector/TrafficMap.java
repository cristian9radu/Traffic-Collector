package ro.pub.acs.traffic.collector;

import android.app.Activity;

public class TrafficMap extends Activity {
	
}
/*
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

import ro.pub.acs.traffic.utils.Database;
import ro.pub.acs.traffic.utils.Results;
import ro.pub.acs.traffic.utils.Utils;

import android.app.AlertDialog;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.graphics.Paint;
import android.graphics.Point;
import android.graphics.Paint.Style;
import android.graphics.drawable.Drawable;
import android.location.Address;
import android.location.Geocoder;
import android.os.Bundle;
import android.os.IBinder;
import android.os.PowerManager;
import android.telephony.TelephonyManager;
import android.telephony.gsm.GsmCellLocation;
import android.widget.TextView;

import com.google.android.maps.GeoPoint;
import com.google.android.maps.ItemizedOverlay;
import com.google.android.maps.MapActivity;
import com.google.android.maps.MapController;
import com.google.android.maps.MapView;
import com.google.android.maps.Overlay;
import com.google.android.maps.OverlayItem;

class DataGatherer extends Thread {
	private TrafficMap parentActivity;
	private static final int SLEEP_TIME = 5;
	
	public DataGatherer(TrafficMap parentActivity) {
		this.parentActivity = parentActivity;
	}
	
	@Override
	public void run() {
		try {
			while(true) {
				if(this.parentActivity.service != null) {
					Results res = this.parentActivity.service.getCurrent();
					if(res.lat != 0)
					{
						Float speed = new Float(res.speed);
						Double lng = new Double(res.log);
						Double lat = new Double(res.lat);
						Double accuracy = new Double(res.accuracy);
						if(accuracy == 0)
							accuracy = new Double(200);
						
						this.parentActivity.currentSpeed = speed;
						this.parentActivity.currentLat = lat;
						this.parentActivity.currentLong = lng;
						this.parentActivity.currentAccuracy = accuracy;
						
						parentActivity.runOnUiThread(new Runnable() 
						{
			                @Override
			                public void run() 
			                {
			                	parentActivity.receivedData();
			                }
						});
					}
				}
				Thread.sleep(SLEEP_TIME * 1000);
			}
		} catch (InterruptedException e) {
			e.printStackTrace();
		}
	}
}

public class TrafficMap extends MapActivity {
	public TrafficCollectorService service;
	private MapController mapController;
	private MapView mapView;
	
	private Database db_statistics;
	
	private TextView tvSpeed, tvLength;
	
	public float currentSpeed = -1;
	public double currentLat = 44.438415, currentLong = 26.067799;
	public double currentAccuracy = 200;
	private Thread gatherDataThread;
	private TelephonyManager telephonyManager;
    private GsmCellLocation cellLocation;
    
    private List<Overlay> mapOverlays;
    private Drawable drawable;
    private MapItemizedOverlay itemizedOverlay;
    
    private PowerManager powerManager;
    private PowerManager.WakeLock screenLock;
	
	private ServiceConnection mConnection = new ServiceConnection() {

		public void onServiceConnected(ComponentName className, IBinder binder) {
			service = ((TrafficCollectorService.MyBinder) binder).getService();
		}

		public void onServiceDisconnected(ComponentName className) {
			service = null;
		}
	};

	public void onCreate(Bundle bundle) {
		super.onCreate(bundle);
		
		powerManager = (PowerManager)getSystemService(Context.POWER_SERVICE);
		screenLock = powerManager.newWakeLock(PowerManager.FULL_WAKE_LOCK, "ScreenWL");
		
		screenLock.acquire();
		
		telephonyManager = (TelephonyManager)getSystemService(Context.TELEPHONY_SERVICE);
		cellLocation = (GsmCellLocation)telephonyManager.getCellLocation();
		
		if(TrafficCollectorService.isInstanceCreated()) {
			bindService(new Intent(this, TrafficCollectorService.class), mConnection, 0);
		}
		
		setContentView(R.layout.map); // bind the layout to the activity

		// create a map view
		//RelativeLayout linearLayout = (RelativeLayout) findViewById(R.id.mainlayout);
		mapView = (MapView) findViewById(R.id.mapview);
		tvLength = (TextView) findViewById(R.id.map_length);
		tvSpeed = (TextView) findViewById(R.id.map_speed);
		
		mapView.setBuiltInZoomControls(true);
		mapController = mapView.getController();
		mapController.setZoom(18);
		mapOverlays = mapView.getOverlays();
		mapOverlays.clear();
		drawable = this.getResources().getDrawable(R.drawable.overlay_image);
		itemizedOverlay = new MapItemizedOverlay(drawable, this, 30, this);//text size: 30
		try {
			Results currentPos = Utils.getCellLocation(cellLocation.getCid(), cellLocation.getLac());
			if(currentPos != null) {
				currentLat = currentPos.lat;
				currentLong = currentPos.log;
				currentSpeed = currentPos.speed;
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
		
		try {
			gatherDataThread =  new DataGatherer(this);
			gatherDataThread.start();
			receivedData();
		} catch(Exception ex){
			ex.printStackTrace();
		}
	}
	
	public void receivedData() {
		db_statistics = new Database(this, "collector", "statistics", new String[] { "speed", "max_speed", "avg_speed", "length", "no", "uuid" });
		int speed = (int) (Float.parseFloat(db_statistics.get("speed")) * 3.6);
		if(speed <= 0)
			speed = 0;
		double length = Math.round(Double.parseDouble(db_statistics.get("length")));
		if(length == -1)
			length = 0;
		
		tvLength.setText(length + " km");
		tvSpeed.setText(speed + " km/h");
		
		GeoPoint mapPoint = new GeoPoint((int) (currentLat * 1E6), (int) (currentLong * 1E6));
		Geocoder geoCoder = new Geocoder(this, Locale.getDefault());
		String add = ""; 
        
		mapController.animateTo(mapPoint);
		try {
			 List<Address> addresses = geoCoder.getFromLocation(currentLat, currentLong, 1);
             
             if (addresses.size() > 0) {
            	 add = "(" + addresses.get(0).getLatitude() + "," + addresses.get(0).getLongitude() + ")\n\n";
            	 for (int i=0; i<addresses.get(0).getMaxAddressLineIndex(); i++)
			         add += addresses.get(0).getAddressLine(i) + "\n";
            	 add += "\n\nSpeed: " + currentSpeed;
			 }
		} catch (IOException e) {
		     e.printStackTrace();
		}
		mapOverlays.clear();
		itemizedOverlay.clear();
		//itemizedOverlay = new MapItemizedOverlay(drawable, this, 30, this);//text size: 30
        OverlayItem overlayItem = new OverlayItem(mapPoint, "Me", add);
        itemizedOverlay.addOverlay(overlayItem);
        mapOverlays.add(itemizedOverlay);
        
        mapView.invalidate();
        
	}

	@Override
	protected boolean isRouteDisplayed() {
		return false;
	}
	
	public void onStop() {
		super.onStop();
		db_statistics.close();
		if (screenLock.isHeld())
			screenLock.release();
		if(TrafficCollectorService.isInstanceCreated())
			try {
				unbindService(mConnection);
			} catch (Exception e) {
				return;
			}
	}
}

class MapItemizedOverlay extends ItemizedOverlay<OverlayItem>
{
    //member variables
    private ArrayList<OverlayItem> mOverlays = new ArrayList<OverlayItem>();
    private Context mContext;
    private TrafficMap tm;
    private int mTextSize;


    public MapItemizedOverlay(Drawable defaultMarker, Context context, int textSize, TrafficMap tm)
    {
        super(boundCenterBottom(defaultMarker));
        mContext = context;
        mTextSize = textSize;
        this.tm = tm;
    }


    //In order for the populate() method to read each OverlayItem, it will make a request to createItem(int)
    // define this method to properly read from our ArrayList
    @Override
    protected OverlayItem createItem(int i)
    {
        return mOverlays.get(i);
    }


    @Override
    public int size()
    {
        return mOverlays.size();
    }

    @Override
    protected boolean onTap(int index)
    {
        OverlayItem item = mOverlays.get(index);
       
        //Do stuff here when you tap, i.e. :
        AlertDialog.Builder dialog = new AlertDialog.Builder(mContext);
        dialog.setTitle(item.getTitle());
        dialog.setMessage(item.getSnippet());
        dialog.show();

        //return true to indicate we've taken care of it
        return true;
    }

    @Override
    public void draw(android.graphics.Canvas canvas, MapView mapView, boolean shadow)
    {
        super.draw(canvas, mapView, shadow);

        if (shadow == false)
        {
            //cycle through all overlays
            for (int index = 0; index < mOverlays.size(); index++)
            {
                OverlayItem item = mOverlays.get(index);

                // Converts lat/lng-Point to coordinates on the screen
                GeoPoint point = item.getPoint();
                Point ptScreenCoord = new Point() ;
                mapView.getProjection().toPixels(point, ptScreenCoord);

                //Paint
                Paint paint = new Paint();
                paint.setTextAlign(Paint.Align.CENTER);
                paint.setTextSize(mTextSize);
                paint.setARGB(150, 0, 0, 0); // alpha, r, g, b (Black, semi see-through)

                //show text to the right of the icon
                //canvas.drawText(item.getTitle(), ptScreenCoord.x, ptScreenCoord.y+mTextSize, paint);
                
                Paint circlePaint = new Paint(Paint.ANTI_ALIAS_FLAG);
        		circlePaint.setColor(0x30000000);
        		circlePaint.setStyle(Style.FILL_AND_STROKE);
        		int radius = (int) mapView.getProjection().metersToEquatorPixels(Math.round(tm.currentAccuracy));
        		canvas.drawCircle(ptScreenCoord.x, ptScreenCoord.y, radius, circlePaint);
            }
        }
    }


    public void addOverlay(OverlayItem overlay)
    {
        mOverlays.add(overlay);
        populate();
    }


    public void removeOverlay(OverlayItem overlay)
    {
        mOverlays.remove(overlay);
        populate();
    }


    public void clear()
    {
        mOverlays.clear();
        populate();
    }

}*/