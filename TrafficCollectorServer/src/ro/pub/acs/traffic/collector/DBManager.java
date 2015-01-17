package ro.pub.acs.traffic.collector;

/**
 * 
 */

import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.ResultSetMetaData;
import java.sql.SQLException;

import com.mysql.jdbc.Connection;
import com.mysql.jdbc.PreparedStatement;
import com.mysql.jdbc.Statement;

/**
 * @author catalin
 *
 */
public class DBManager {
	
	private String DRIVER	= "com.mysql.jdbc.Driver";
	private String IP		= "localhost";
	private String DB		= "traffic_collector";
	private String USER		= "root";
	private String PASS		= "";
	
	final String SEP	= "\t\t";
	
	public Connection conn;

	public static void main(String[] args)
	{
		DBManager bd = new DBManager();
		bd.getId();
	}
	 
	public DBManager()
	{
		try
		{
			Class.forName(DRIVER).newInstance();
			String url = "jdbc:mysql://" + IP + "/" + DB;
			conn = (Connection) DriverManager.getConnection(url, USER, PASS);
		}
		catch (ClassNotFoundException ex) {System.err.println(ex.getMessage());}
		catch (IllegalAccessException ex) {System.err.println(ex.getMessage());}
		catch (InstantiationException ex) {System.err.println(ex.getMessage());}
		catch (SQLException ex)           {System.err.println(ex.getMessage());}
	}
	
	public Connection getConn()
	{
		return this.conn;
	}
	
	public int getId()
	{
		int index = 0;
		
		try
		{
			Statement st = (Statement) conn.createStatement();
			ResultSet rs = st.executeQuery("SELECT id FROM location ORDER BY id DESC LIMIT 0, 1");
			while (rs.next())
				index = Integer.parseInt(rs.getString(1));
		}
		catch (SQLException ex)
		{
			System.err.println(ex.getMessage());
		}
		return index;
		
	}
	
	public void doSelectQuery(String query)
	{
		try
		{
			Statement st = (Statement) conn.createStatement();
			ResultSet rs = st.executeQuery(query);
			ResultSetMetaData rsmd = rs.getMetaData();
			int columns = rsmd.getColumnCount();
			for (int i = 1; i <= columns; i++)
				System.out.print(rsmd.getColumnName(i).toUpperCase() + SEP);
			System.out.println();
			
			while (rs.next()) {
				for (int i = 1; i <= columns; i++)
					System.out.print(rs.getString(i) + SEP);
				System.out.println();
			}
		}
		catch (SQLException ex)
		{
			System.err.println(ex.getMessage());
		}
	}
	
	public void doPreparedQuery(String query, String[] values)
	{
		PreparedStatement stmt = null;
		int i;
		try
	    {
			stmt = (PreparedStatement) conn.prepareStatement(query);
			for(i = 0; i < values.length; i++)
				stmt.setString(i + 1, values[i]);
			stmt.executeUpdate();
	    }
	    catch (Exception ex)
	    {
	    	System.err.println(ex.getMessage());
	    }
	}

	public void doQuery(String query)
	{
		try
	    {
	    	Statement st = (Statement) conn.createStatement();
	    	st.executeUpdate(query);
	    }
	    catch (SQLException ex)
	    {
	    	System.err.println(ex.getMessage());
	    }
	}
	
	public void close()
	{
		try {
			this.conn.close();
		} catch (SQLException e) {
			e.printStackTrace();
		}
	}
}
