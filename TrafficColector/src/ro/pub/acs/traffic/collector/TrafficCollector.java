package ro.pub.acs.traffic.collector;

import android.app.TabActivity;
import android.content.Intent;
import android.os.Bundle;
import android.widget.TabHost;

public class TrafficCollector extends TabActivity {
    @Override
    public void onCreate(Bundle savedInstanceState) {
    	super.onCreate(savedInstanceState);
        setContentView(R.layout.main_tab);

        TabHost tabHost = getTabHost();
        TabHost.TabSpec spec;
        Intent intent;

        // create an Intent to launch an Activity for the tab.
        intent = new Intent().setClass(this, TrafficCollectorMain.class);

        // initialize a TabSpec for each tab and add it to the TabHost.
        spec = tabHost.newTabSpec("main").setIndicator("Main").setContent(intent);
        tabHost.addTab(spec);

        // do the same for the other tab.
        intent = new Intent().setClass(this, TrafficCollectorAbout.class);
        spec = tabHost.newTabSpec("about").setIndicator("About").setContent(intent);
        tabHost.addTab(spec);

        // set the main tab as the default one.
        tabHost.setCurrentTab(0);
    }
}