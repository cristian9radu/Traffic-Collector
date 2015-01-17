package ro.pub.acs.traffic.utils;

public class Results {
	public float speed;
	public double log, lat;
	public long timestamp;
	public double accuracy;
	
	public Results(float speed, double log, 
			double lat, long timestamp) {
		this.speed = speed;
		this.log = log;
		this.lat = lat;
		this.timestamp = timestamp;
	}
	
	public String toString() {
		return this.log + " " + this.lat + " " + this.speed + " " + this.timestamp;
	}
}