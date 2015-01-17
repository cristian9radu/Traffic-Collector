package ro.pub.acs.traffic.collector;

import java.util.Vector;

import ro.pub.acs.traffic.utils.Database;
import ro.pub.acs.traffic.utils.Gauge;
import android.app.Activity;
import android.content.Context;
import android.os.Bundle;
import android.os.PowerManager;
import android.widget.TextView;

class StatisticGatherer extends Thread {
	private TrafficCollectorSpeed parentActivity;
	private static final int SLEEP_TIME = 1;
	
	public StatisticGatherer(TrafficCollectorSpeed parentActivity) {
		this.parentActivity = parentActivity;
	}
	
	@Override
	public void run() {
		try {
			while(true) {
				parentActivity.runOnUiThread(new Runnable() 
				{
	                @Override
	                public void run() 
	                {
	                	parentActivity.receivedData();
	                }
				});
				Thread.sleep(SLEEP_TIME * 100);
			}		
		} catch (InterruptedException e) {
			e.printStackTrace();
		}
	}
}

public class TrafficCollectorSpeed extends Activity {
	private Gauge view;
	private TextView speedTV;
	private TextView maxSpeedTV;
	private TextView lengthTV;
	public Vector<Double> resultTime;
	public Vector<Double> resultValues;
	
	private PowerManager powerManager;
    private PowerManager.WakeLock screenLock;
    
    private Database db_statistics;

    private Thread gatherDataThread;
    
	@Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.speed);
        view = (Gauge)this.findViewById(R.id.gauge);
        speedTV = (TextView) this.findViewById(R.id.speed);
        maxSpeedTV = (TextView) this.findViewById(R.id.max_speed);
        lengthTV = (TextView) this.findViewById(R.id.length);
        
        gatherDataThread =  new StatisticGatherer(this);
		gatherDataThread.start();
        
        receivedData();
		   
        powerManager = (PowerManager)getSystemService(Context.POWER_SERVICE);
		screenLock = powerManager.newWakeLock(PowerManager.FULL_WAKE_LOCK, "ScreenWL");
		
		screenLock.acquire();
    }
	
	public void receivedData()
	{
		String speed = "0";
		
		db_statistics = new Database(this, "collector", "statistics", new String[] { "speed", "max_speed", "avg_speed", "length", "no", "uuid" });
	    if(db_statistics.isEmpty())
	    	db_statistics.insert(new String[] {"-1", "-1", "-1", "-1", "-1", "-1"});
	    speed = db_statistics.get("speed");
	    view.setHandTarget((int) (Float.parseFloat(speed) * 3.6));
		if(speed.compareTo("-1") == 0)
			speed = "0";
		speedTV.setText("" + Math.round((Float.parseFloat(speed) * 3.6)));
		String maxSpeed = db_statistics.get("max_speed");
		if(maxSpeed.compareTo("-1") == 0)
			maxSpeed = "0";
		double length = ((double)Math.round(Double.parseDouble(db_statistics.get("length")) * 1000))/1000;
		maxSpeedTV.setText("" + Math.round(Float.parseFloat(maxSpeed) * 3.6));
		
		lengthTV.setText("" + (length == -1 ? "N/A" : length));
		db_statistics.close();
	}
	
	public void onStop() {
		super.onStop();
		if (screenLock.isHeld())
			screenLock.release();
	}
}