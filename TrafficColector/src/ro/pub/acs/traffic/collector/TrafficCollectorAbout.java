package ro.pub.acs.traffic.collector;

import android.app.Activity;
import android.os.Bundle;
import android.webkit.WebView;

public class TrafficCollectorAbout extends Activity {
	public void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		WebView view = new WebView(this);
		String content = "Traffic congestions are realities of urban environments. The road infrastructure capacities " +
						"cannot cope with the rate of increase socket_reader the number of cars. This, coupled with traffic incidents, "+
						"work zones, weather conditions, make traffic congestions one major concern for municipalities " + 
						"and research organizations." + 
						"<br/><br/>Traffic Collector is an application that gathers information about daily traffic. The idea is " +
						"to collect data that can be used to construct a model of the traffic patterns socket_reader a large city such" +
						" as Bucharest. This means getting data about the traffic on a particular road, depending on the " + 
						"hour of the day or time of the week for example. The model can be used to make predictions about " + 
						"traffic, to construct smart navigation application that might tell you to avoid a certain route " + 
						"because it's always congested at this time of the day. We rely on public crowds (meaning you) to collect the data, and give back freely " + 
						"the obtained data to anyone interesting (everything is public).<br/><br/>" + 
						"The project is developed socket_reader a joint collaboration between University POLITEHNICA of Bucharest " + 
						"[1] and Rutgers University [2].\n\n" + 
						"For more information or if you find any bugs, please visit <a href=\"http://code.google.com/p/traffic-collector/\">http://code.google.com/p/traffic-collector/</a>"+
						"<br/><br/>"+
						"[1] <a href=\"http://cipsm.hpc.pub.ro/vanet/\">University POLITEHNICA of Bucharest</a><br/>" +
						"[2] <a href=\"http://http://discolab.rutgers.edu/\">Rutgers University</a>";
		String html = "<html>" +
				 "<head></head>" + 
				 "<body style=\"text-align:justify;color:gray;background-color:black; font-size: 10px;\">" + 
				  content +
				 "</body>" +
				"</html>";
		view.setVerticalScrollBarEnabled(false);
		view.setHorizontalScrollBarEnabled(false);
		view.loadData(html, "text/html", "utf-8");
		setContentView(view);
    }
}