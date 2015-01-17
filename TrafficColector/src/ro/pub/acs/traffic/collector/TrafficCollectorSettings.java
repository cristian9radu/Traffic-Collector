package ro.pub.acs.traffic.collector;

import ro.pub.acs.traffic.utils.CryptTool;
import ro.pub.acs.traffic.utils.Database;
import ro.pub.acs.traffic.utils.HashString;
import ro.pub.acs.traffic.utils.Utils;
import android.app.Dialog;
import android.app.ProgressDialog;
import android.os.Bundle;
import android.os.Handler;
import android.os.Message;
import android.preference.CheckBoxPreference;
import android.preference.EditTextPreference;
import android.preference.Preference;
import android.preference.PreferenceActivity;
import android.preference.Preference.OnPreferenceChangeListener;
import android.util.Base64;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.Toast;

public class TrafficCollectorSettings extends PreferenceActivity 
{
	private EditTextPreference name;
	private EditTextPreference username;
	private CheckBoxPreference change;
	private CheckBoxPreference update_server;
	
	private static final String updateURL = "http://cipsm.hpc.pub.ro/traffic/password_update.php";
	private EditTextPreference password;
	private EditTextPreference password_re;
	//private EditTextPreference facebook;
	//private EditTextPreference twitter;
	
	private PreferenceActivity thisActivity;
	
	private Database db_user;
	
	/** Called when the activity is first created. */
	@Override
	public void onCreate(Bundle savedInstanceState) 
	{
		super.onCreate(savedInstanceState);
		addPreferencesFromResource(R.layout.settings);
		
		thisActivity = this;
		
		db_user = new Database(this, "collector", "user", new String[] { "username", "password", "uuid" });
		//db_user.clearTable();
		name = (EditTextPreference)this.findPreference("settings_name");
		username = (EditTextPreference)this.findPreference("settings_username");
		change = (CheckBoxPreference)this.findPreference("settings_change");
		update_server = (CheckBoxPreference)this.findPreference("settings_update_server");
		
		String local_username = db_user.isEmpty() ? "" : db_user.get("username");
		String local_name = db_user.isEmpty() ? "" : CryptTool.bytes2String(Base64.decode(db_user.get("name").getBytes(), Base64.NO_WRAP));
		
		password = (EditTextPreference)this.findPreference("settings_password");
		password_re = (EditTextPreference)this.findPreference("settings_password_re");
		
		if(!name.getText().equals(""))
			name.setSummary((CharSequence) name.getText());
		else {
			name.setText(local_name);
			name.setSummary(local_name);
		}
		if(!username.getText().equals(""))
			username.setSummary((CharSequence) username.getText());
		else {
			username.setSummary(local_username);
			username.setText(local_username);
		}
		
		if(local_name.equals("")) {
			name.setText("");
			name.setSummary("");
		}
		
		if(local_username.equals("")) {
			username.setText("");
			username.setSummary("");
		}
		
		name.setOnPreferenceChangeListener(new OnPreferenceChangeListener() 
		{
			@Override
			public boolean onPreferenceChange(Preference preference, Object newValue) 
			{	
				String value = newValue.toString();
				if(value.indexOf("#") != -1) {
					Utils.showError(thisActivity, "Name");
					return false;
				}
				preference.setSummary(value);
				if(!db_user.isOpen())
					db_user = new Database(thisActivity, "collector", "user", new String[] { "username", "password", "uuid" });
				db_user.update(new String[] {"name"}, new String[] {Base64.encodeToString(value.getBytes(), Base64.NO_WRAP)});
				
				return false;
			}
		});
		username.setOnPreferenceChangeListener(new OnPreferenceChangeListener() 
		{
			@Override
			public boolean onPreferenceChange(Preference preference, Object newValue) 
			{	
				String value = newValue.toString();
				if(!Utils.isValidEmailAddress(value)) {
					Utils.showCustomError(thisActivity, "Username must be a valid email!");
					return false;
				}
				if(value.indexOf("#") != -1) {
					Utils.showError(thisActivity, "Username");
					return false;
				}
				preference.setSummary(value);
				if(!db_user.isOpen())
					db_user = new Database(thisActivity, "collector", "user", new String[] { "username", "password", "uuid" });
				db_user.update(new String[] {"username"}, new String[] {value});
				
				return false;
			}
		});
		
		change.setOnPreferenceChangeListener(new OnPreferenceChangeListener() 
		{
			@Override
			public boolean onPreferenceChange(Preference preference, Object newValue) 
			{	
				if(new Boolean(newValue.toString()) == true)
				{
					change.setChecked(true);
					final Dialog alertDialog = new Dialog(thisActivity);
					
					alertDialog.setContentView(R.layout.change_password);
					alertDialog.setTitle("Change Password");
					// Set an EditText view to get user input 
					final EditText password = (EditText) alertDialog.findViewById(R.id.password_ch);
					final EditText password_check = (EditText) alertDialog.findViewById(R.id.password_check_ch);
					final Button save = (Button) alertDialog.findViewById(R.id.account_save_ch);
					final Button cancel = (Button) alertDialog.findViewById(R.id.account_cancel_ch);
					
					save.setOnClickListener(new View.OnClickListener() {
						public void onClick(View v) {
							HashString hs = new HashString("SHA1");
							String _password = password.getText().toString();
							String _password_check = password_check.getText().toString();
							String errorText = null;
							if(_password == null || _password.equals(""))
								errorText = "Please provide password!";
							else if(_password_check == null || _password_check.equals(""))
								errorText = "Please provide password check!";
							else if(!_password_check.equals(_password))
								errorText = "Passwords do not match!";
							
							if(errorText != null)
								Utils.showDialog(thisActivity, errorText);
							else {
								Utils.showDialog(thisActivity, "Passwords modified! The modification will be propagated on the server when you upload or enable real time!");
								if(!db_user.isOpen())
									db_user = new Database(thisActivity, "collector", "user", new String[] { "username", "password", "uuid" });
								db_user.update(new String[] {"password"}, new String[] {hs.hash(_password)});
								update_server.setEnabled(true);
								alertDialog.cancel();
							}
							change.setChecked(false);
						}
					});
					
					cancel.setOnClickListener(new View.OnClickListener() {
						public void onClick(View v) {
							alertDialog.cancel();
						}
					});
					
					alertDialog.show();
				}
				else
				{
					change.setChecked(false);
				}
				return false;
			}
		});
		
		update_server.setOnPreferenceChangeListener(new OnPreferenceChangeListener() 
		{
			@Override
			public boolean onPreferenceChange(Preference preference, Object newValue) 
			{
				if(new Boolean(newValue.toString()) == true)
				{
					final ProgressDialog dialog = ProgressDialog.show(thisActivity, "", "Sending updated account information to server!", true);
					final Handler handler = new Handler() {
			    		public void handleMessage(Message msg) {
			    			dialog.dismiss();
			    			Toast toast = null;
			    			toast = Toast.makeText(thisActivity, "Account information have been updated to server!", 4000);
			    		    toast.show();
			    		}
			    	};
			    	
			    	Thread checkUpdate = new Thread() {  
			    		public void run() {
			    			CryptTool ct = new CryptTool();
			    			if(!db_user.isOpen())
								db_user = new Database(thisActivity, "collector", "user", new String[] { "username", "password", "uuid" });
			    			String lname = db_user.get("name").equals("") ? "0" : ct.encrypt(db_user.get("name"));
		                	String lusername = db_user.get("username").equals("") ? "0" : ct.encrypt(db_user.get("username"));
		                	String lpassword = db_user.get("password").equals("") ? "0" : ct.encrypt(db_user.get("password"));
		                	
							Utils.sendPost(thisActivity, ct.encrypt(db_user.get("uuid")), lname, lusername, lpassword, updateURL);
			    			handler.sendEmptyMessage(0);
			    		}
			    	};
			    	checkUpdate.start();
				}
			    return false;
			}
		});
				
		/*facebook = (EditTextPreference)this.findPreference("settings_facebook");
		if(!facebook.getText().equals(""))
			facebook.setSummary((CharSequence) facebook.getText());
		facebook.setOnPreferenceChangeListener(new OnPreferenceChangeListener() 
		{
			@Override
			public boolean onPreferenceChange(Preference preference, Object newValue) 
			{	
				String value = newValue.toString();
				if(value.indexOf("#") != -1) {
					Utils.showError(thisActivity, "Facebook");
					return false;
				}
				
				preference.setSummary(value);
				
				return false;
			}
		});
		twitter = (EditTextPreference)this.findPreference("settings_twitter");
		if(!twitter.getText().equals(""))
			twitter.setSummary((CharSequence) twitter.getText());
		twitter.setOnPreferenceChangeListener(new OnPreferenceChangeListener() 
		{
			@Override
			public boolean onPreferenceChange(Preference preference, Object newValue) 
			{	
				String value = newValue.toString();
				if(value.indexOf("#") != -1) {
					Utils.showError(thisActivity, "Twitter");
					return false;
				}
				
				preference.setSummary(value);
				
				return false;
			}
		});*/
		db_user.close();
	}
}