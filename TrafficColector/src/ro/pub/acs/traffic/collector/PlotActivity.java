package ro.pub.acs.traffic.collector;

import java.util.Vector;

import ro.pub.acs.traffic.utils.Results;
import ro.pub.acs.traffic.utils.XYLineChartView;

import net.droidsolutions.droidcharts.core.data.XYDataset;
import net.droidsolutions.droidcharts.core.data.xy.XYSeries;
import net.droidsolutions.droidcharts.core.data.xy.XYSeriesCollection;

import android.app.Activity;
import android.content.ComponentName;
import android.content.Intent;
import android.content.ServiceConnection;
import android.os.Bundle;
import android.os.IBinder;

class Gatherer extends Thread {
	private PlotActivity parentActivity;
	private static final int SLEEP_TIME = 1;
	private static final int RANGE = 10;
	
	public Gatherer(PlotActivity parentActivity) {
		this.parentActivity = parentActivity;
	}
	
	@Override
	public void run() {
		try {
			while(true) {
				if(this.parentActivity.service != null) {
					Results res = this.parentActivity.service.getCurrent();
				
					Double timestamp = new Double(res.timestamp);
					Double speed = new Double(res.speed);
					this.parentActivity.resultTime.add(timestamp);
					this.parentActivity.resultValues.add(speed);
					if(this.parentActivity.resultTime.size() == RANGE + 1) {
						this.parentActivity.resultTime.remove(0);
						this.parentActivity.resultValues.remove(0);
					}
					parentActivity.runOnUiThread(new Runnable() 
					{
		                @Override
		                public void run() 
		                {
		                	parentActivity.receivedData();
		                }
					});
				}
				Thread.sleep(SLEEP_TIME * 1000);
			}
		} catch (InterruptedException e) {
			e.printStackTrace();
		}
	}
}

public class PlotActivity extends Activity {
	
	public TrafficCollectorService service;
	private static final String xLabel = "Time";
	private static final String yLabel = "Speed (km/h)";
	private static final String title = "Speed";
	public Vector<Double> resultTime;
	public Vector<Double> resultValues;
	
	private Thread gatherDataThread;
	
	private ServiceConnection mConnection = new ServiceConnection() {

		public void onServiceConnected(ComponentName className, IBinder binder) {
			service = ((TrafficCollectorService.MyBinder) binder).getService();
		}

		public void onServiceDisconnected(ComponentName className) {
			service = null;
		}
	};
	
	public void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);

		if(TrafficCollectorService.isInstanceCreated()) {
			bindService(new Intent(this, TrafficCollectorService.class), mConnection, 0);
		}
		try {
			gatherDataThread =  new Gatherer(this);
			gatherDataThread.start();
			this.resultTime = new Vector<Double>();
			this.resultValues = new Vector<Double>();
			receivedData();
		} catch(Exception ex){
			ex.printStackTrace();
		}
		
    }
	
	public XYDataset XYCreateDataset(String chartTitle, Vector<Double> resultTime, Vector<Double> resultValues)
	{
		final XYSeriesCollection dataset = new XYSeriesCollection();
		final XYSeries series1 = new XYSeries(chartTitle);
		for(int i = 0; i < resultTime.size(); i++) {
			series1.add(resultTime.elementAt(i).doubleValue(), resultValues.elementAt(i).doubleValue() * 3.6);
		}
		dataset.addSeries(series1);
		return dataset;
	}
	
	public void receivedData()
	{
		XYDataset dataset = XYCreateDataset(title, this.resultTime, this.resultValues);
		XYLineChartView graphView = new XYLineChartView(this, title, xLabel, yLabel, dataset);
		setContentView(graphView);
	}
	
	public void onStop() {
		super.onStop();
		if(TrafficCollectorService.isInstanceCreated())
			try {
				unbindService(mConnection);
			} catch (Exception e) {
				return;
			}
	}
	
	
}