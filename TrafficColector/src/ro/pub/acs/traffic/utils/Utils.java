/**
 * Different Utilities Class.
 * @author Fratila Catalin Ionut
 */

package ro.pub.acs.traffic.utils;

import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLConnection;
import java.net.URLEncoder;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import ro.pub.acs.traffic.collector.TrafficCollectorMain;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.Context;
import android.content.DialogInterface;
import android.net.ConnectivityManager;
import android.os.Environment;
import android.widget.Toast;

public class Utils {
	public static boolean testCard() {
		boolean mExternalStorageAvailable = false;
		boolean mExternalStorageWriteable = false;
		String state = Environment.getExternalStorageState();

		if (Environment.MEDIA_MOUNTED.equals(state)) {
		    // We can read and write the media
		    mExternalStorageAvailable = mExternalStorageWriteable = true;
		} else if (Environment.MEDIA_MOUNTED_READ_ONLY.equals(state)) {
		    // We can only read the media
		    mExternalStorageAvailable = true;
		    mExternalStorageWriteable = false;
		} else {
		    // Something else is wrong. It may be one of many other states, but all we need
		    //  to know is we can neither read nor write
		    mExternalStorageAvailable = mExternalStorageWriteable = false;
		}
		return mExternalStorageAvailable && mExternalStorageWriteable;
	}
	
	public static boolean checkInternetConnection(Activity activity) {
	    ConnectivityManager cm = (ConnectivityManager) activity.getSystemService(Context.CONNECTIVITY_SERVICE);
	    if (cm.getActiveNetworkInfo() != null
	            && cm.getActiveNetworkInfo().isAvailable()
	            && cm.getActiveNetworkInfo().isConnected()) {
	        return true;
	    } else {
	        return false;
	    }
	}
	
	public static void showError(Activity thisActivity, String param) {
		AlertDialog alertDialog = new AlertDialog.Builder(thisActivity).create();
		alertDialog.setMessage(param + " field should not contain '#'!");
		alertDialog.setButton("Ok", new DialogInterface.OnClickListener() {
		      public void onClick(DialogInterface dialog, int which) {
		    	  dialog.cancel();
		      }
		});
		alertDialog.show();
	}
	
	public static void showCustomError(Activity thisActivity, String error) {
		AlertDialog alertDialog = new AlertDialog.Builder(thisActivity).create();
		alertDialog.setMessage(error);
		alertDialog.setButton("Ok", new DialogInterface.OnClickListener() {
		      public void onClick(DialogInterface dialog, int which) {
		    	  dialog.cancel();
		      }
		});
		alertDialog.show();
	}
	
	public static double gps2m(double lat_a, double lng_a, double lat_b, double lng_b) {
		double pk = (double) (180/Math.PI);
		
		double a1 = lat_a / pk;
		double a2 = lng_a / pk;
		double b1 = lat_b / pk;
		double b2 = lng_b / pk;
		
		double t1 = Math.cos(a1)*Math.cos(a2)*
				Math.cos(b1)*Math.cos(b2);
		double t2 = Math.cos(a1)*Math.sin(a2)*
				Math.cos(b1)*Math.sin(b2);
		double t3 = Math.sin(a1)*Math.sin(b1);
		double tt = Math.acos(t1 + t2 + t3);
		 
		return 6366*tt;
	}
	
	private static double deg2rad(double deg) {
	  return (deg * Math.PI / 180.0);
	}

	public static double distance_haversine(double lat_a, double lon_a, double lat_b, double lon_b) {
		double earth_radius = 3960.00;
		double delta_lat = lat_b - lat_a;
		double delta_lon = lon_b - lon_a;
		double alpha     = delta_lat/2;
		double beta      = delta_lon/2;
		double a         = Math.sin(deg2rad(alpha)) * Math.sin(deg2rad(alpha)) + Math.cos(deg2rad(lat_a)) * Math.cos(deg2rad(lat_b)) * Math.sin(deg2rad(beta)) * Math.sin(deg2rad(beta)) ;
		double c         = Math.asin(Math.min(1, Math.sqrt(a)));
		double distance  = 2 * earth_radius * c;
		distance = ((double)Math.round(distance * 1.609344 * 10000))/10000;
		return distance;
	}
	
	private static void WriteData(OutputStream out, int cellID, int lac) throws IOException {    	
        DataOutputStream dataOutputStream = new DataOutputStream(out);
        dataOutputStream.writeShort(21);
        dataOutputStream.writeLong(0);
        dataOutputStream.writeUTF("en");
        dataOutputStream.writeUTF("Android");
        dataOutputStream.writeUTF("1.0");
        dataOutputStream.writeUTF("Web");
        dataOutputStream.writeByte(27);
        dataOutputStream.writeInt(0);
        dataOutputStream.writeInt(0);
        dataOutputStream.writeInt(3);
        dataOutputStream.writeUTF("");

        dataOutputStream.writeInt(cellID);  
        dataOutputStream.writeInt(lac);     

        dataOutputStream.writeInt(0);
        dataOutputStream.writeInt(0);
        dataOutputStream.writeInt(0);
        dataOutputStream.writeInt(0);
        dataOutputStream.flush();    	
    }
	
	public static Results getCellLocation(int cellID, int lac) throws Exception {
        String urlString = "http://www.google.com/glm/mmap";            
    
        //---open a connection to Google Maps API---
        URL url = new URL(urlString); 
        URLConnection conn = url.openConnection();
        HttpURLConnection httpConn = (HttpURLConnection) conn;        
        httpConn.setRequestMethod("POST");
        httpConn.setDoOutput(true); 
        httpConn.setDoInput(true);
        httpConn.connect(); 
        
        //---write some custom data to Google Maps API---
        OutputStream outputStream = httpConn.getOutputStream();
        WriteData(outputStream, cellID, lac);       
        
        //---get the response---
        InputStream inputStream = httpConn.getInputStream();  
        DataInputStream dataInputStream = new DataInputStream(inputStream);
        
        //---interpret the response obtained---
        dataInputStream.readShort();
        dataInputStream.readByte();
        int code = dataInputStream.readInt();
        if (code == 0) {
			double lat = (double) dataInputStream.readInt() / 1000000D;
			double lng = (double) dataInputStream.readInt() / 1000000D;
			dataInputStream.readInt();
			dataInputStream.readInt();
			dataInputStream.readUTF();
			Results res = new Results(0, lng, lat, 0);
			
			return res;
        }
        else {        	
        	return null;
        }
    }
	
	public static void sendPost(TrafficCollectorMain activity, String id, String surl, int type, String value) {
		try {
			Toast toast = null;
			URL url = new URL(surl);
			HttpURLConnection connection = (HttpURLConnection) url.openConnection();

			connection.setDoInput(true);
			connection.setDoOutput(true);
			connection.setUseCaches(false);
			connection.setRequestMethod("POST");

			connection.setRequestProperty("Connection", "Keep-Alive");
			connection.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");

			DataOutputStream dataOut = new DataOutputStream(connection.getOutputStream());
			if(type == 0)
				dataOut.writeBytes("anti=10101&stop=" + value + "&id_user=" + id);
			else if(type == 1)
				dataOut.writeBytes("anti=10101&id_user=" + id);
			dataOut.flush();
			
			BufferedReader dataIn = new BufferedReader(new InputStreamReader(connection.getInputStream()));
		    dataIn.readLine();
		    
		    if(type == 0) {
		    	if(value.contains("1")) 
		    		toast = Toast.makeText(activity, "Users cannot see your position anymore!", 4000);
		    	else if(value.contains("0"))
		    		toast = Toast.makeText(activity, "Users cann see your position again!", 4000);
				toast.show();
		    } else if(type == 1) {
		    	
		    }
		    
		    dataIn.close();
			dataOut.close();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	public static void sendPost(Activity activity, String id, String val1, String val2, String val3, String surl) {
		try {
			URL url = new URL(surl);
			HttpURLConnection connection = (HttpURLConnection) url.openConnection();

			connection.setDoInput(true);
			connection.setDoOutput(true);
			connection.setUseCaches(false);
			connection.setRequestMethod("POST");

			connection.setRequestProperty("Connection", "Keep-Alive");
			connection.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");

			DataOutputStream dataOut = new DataOutputStream(connection.getOutputStream());
			dataOut.writeBytes("anti=10101&id_user=" + URLEncoder.encode(id) + "&val1=" + URLEncoder.encode(val1) + "&val2=" + URLEncoder.encode(val2) + "&val3=" + URLEncoder.encode(val3));
			dataOut.flush();
			
			BufferedReader dataIn = new BufferedReader(new InputStreamReader(connection.getInputStream()));
		    
		    System.out.println(dataIn.readLine());
		    
		    
		    
		    dataIn.close();
			dataOut.close();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	public static void showDialog(TrafficCollectorMain activity, String errorMessage) {
		Toast toast = null;
		toast = Toast.makeText(activity, errorMessage, 4000);
		toast.show();
	}
	
	public static void showDialog(Activity activity, String errorMessage) {
		Toast toast = null;
		toast = Toast.makeText(activity, errorMessage, 4000);
		toast.show();
	}
	
	public static boolean isValidEmailAddress(String emailAddress){
	   String  expression="^[\\w\\-]([\\.\\w])+[\\w]+@([\\w\\-]+\\.)+[A-Z]{2,4}$";
	   CharSequence inputStr = emailAddress;
	   Pattern pattern = Pattern.compile(expression,Pattern.CASE_INSENSITIVE);
	   Matcher matcher = pattern.matcher(inputStr);
	   return matcher.matches();
	 }
}