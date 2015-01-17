/**
 * Class for the SQLite General Database access.
 * @author Fratila Catalin Ionut
 */

package ro.pub.acs.traffic.utils;

import java.util.ArrayList;

import org.json.JSONArray;
import org.json.JSONObject;

import android.content.ContentValues;
import android.content.Context;
import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteOpenHelper;

public class Database 
{
	private static final int DB_VERSION = 2;
	private String table;
	private String[] columns;

	private SQLiteDatabase db;
	
	Context context;
	
	private class CustomSQLiteOpenHelper extends SQLiteOpenHelper
	{
		public CustomSQLiteOpenHelper(Context context, String _database, String _table, String[] _columns)
		{
			super(context, _database, null, DB_VERSION);
			table = _table;
			columns = _columns;
		}
		
		@Override
		public void onCreate(SQLiteDatabase db)
		{
			return;
		}

		@Override
		public void onUpgrade(SQLiteDatabase arg0, int arg1, int arg2) 
		{
			return;
		}
	}


	public Database(Context context, String database, String tables, String[] columns) 
	{
		this.context = context;	 
		CustomSQLiteOpenHelper helper = new CustomSQLiteOpenHelper(context, database, tables, columns);
		this.table = tables;
		this.columns = columns;
		this.db = helper.getWritableDatabase();
		String str = "";
		for(int i = 0; i < columns.length; i++)
		{
			str += ", " + columns[i] + " text";
		}
		String newTableQueryString = 	
			"create table if not exists " +
			table +
			"  (id integer primary key autoincrement not null" +
			str +
			");";
		try
		{
			db.execSQL(newTableQueryString);
		} 
		catch(Exception e) 
		{
			e.printStackTrace();
		}
	}
	
	public void clearTable()
	{
		String newTableQueryString = 	
			"DELETE FROM " +
			table ;
		db.execSQL(newTableQueryString);
	}
	
	public boolean isOpen()
	{
		return this.db.isOpen();
	}
	
	public void close()
	{
		this.db.close();
	}

	public long update(String[] params, String[] values)
	{
		long ret;
		ContentValues args = new ContentValues();
		for(int i = 0; i < params.length; i++) {
			args.put(params[i], values[i]);
		}
		ret = db.update(table, args, "", null);
		return ret;
	}
	
	public long insert(String[] _values) 
	{
		ContentValues values = new ContentValues();
		for(int i = 0; i < _values.length; i++)
			values.put(columns[i], _values[i]);
		long ret = db.insert(table, null, values);
		return ret;
	}
	
	public String get(String col)
	{
		String res = "";
		String[] cols = new String[1];
		cols[0] = col;
		Cursor cursor = db.query(table, cols, null, null, null, null, null);
		cursor.moveToFirst();
		res = cursor.getString(0);
		cursor.close();
		return res;
	}

	public boolean delete(long id) 
	{
		return (db.delete(table, "id=" + id, null) > 0);
	}
	
	public boolean isEmpty() 
	{
		try 
		{
			Cursor cursor = db.query(table, columns, null, null, null, null, null);
			int numRows = cursor.getCount();
			cursor.close();
			if(numRows == 0) return true;
			else return false;
		} 
		catch (Exception e) 
		{
			e.printStackTrace();
			return false;
		}
	}

	public ArrayList<ArrayList<String>> getList(String groubBy) 
	{
		ArrayList<ArrayList<String>> valuesList = new ArrayList<ArrayList<String>>();
		ArrayList<String> row;
		String[] cols = new String[columns.length+1];
		cols[0] = "id";
		for(int i=0; i<columns.length; i++)
			cols[i+1] = columns[i];
		try 
		{
			Cursor cursor = db.query(table, cols, null, null, groubBy, null, null);

			int numRows = cursor.getCount();
			cursor.moveToFirst();
			for (int i = 0; i < numRows; ++i) 
			{
				row = new ArrayList<String>();
				for(int j = 0; j < columns.length+1; j++)
					row.add(cursor.getString(j));
				valuesList.add(row);
				cursor.moveToNext();
			}
			cursor.close();
		} 
		catch (Exception e) 
		{
			e.printStackTrace();
		}
		return valuesList;
	}
	
	public JSONArray getListJson(String groubBy) 
	{
		JSONArray valuesList = new JSONArray();
		JSONObject row;
		String[] cols = new String[columns.length+1];
		cols[0] = "id";
		for(int i=0; i<columns.length; i++)
			cols[i+1] = columns[i];
		try 
		{
			Cursor cursor = db.query(table, cols, null, null, groubBy, null, null);

			int numRows = cursor.getCount();
			cursor.moveToFirst();
			for (int i = 0; i < numRows; ++i) 
			{
				row = new JSONObject();
				for(int j = 0; j < columns.length+1; j++) {
					row.put(cols[j], cursor.getString(j));
				}
				valuesList.put(row);
				cursor.moveToNext();
			}
			cursor.close();
		} 
		catch (Exception e) 
		{
			e.printStackTrace();
		}
		return valuesList;
	}
}
