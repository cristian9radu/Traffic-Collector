package ro.pub.acs.traffic.collector;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URLEncoder;
import java.nio.charset.Charset;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.StringTokenizer;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.apache.commons.codec.binary.Base64;

import com.mysql.jdbc.Statement;

class ConnectionThread extends Thread {

	Socket socket;
	boolean debug;
	DBManager db;
	private BufferedReader in;
	private PrintWriter out;
	private BufferedWriter outFile;
	private String filename;

	public static final String DATE_FORMAT_NOW = "yyyy_MM_dd_HH_mm_ss";

	/**
	 * Constructor for the ConnectionThread class.
	 * 
	 * @param socket
	 *            the socket connecting to the client
	 * @param debug
	 *            boolean value for printing debug data
	 */
	public ConnectionThread(Socket socket, boolean debug) {
		this.socket = socket;
		this.debug = debug;

		try {
			in = new BufferedReader(new InputStreamReader(
					socket.getInputStream()));
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return;
		}
		try {
			out = new PrintWriter(socket.getOutputStream(), true);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return;
		}

		// generam fisierul de log
		Calendar cal = Calendar.getInstance();
		SimpleDateFormat sdf = new SimpleDateFormat(DATE_FORMAT_NOW);

		new File("C:\\logs").mkdir();

		filename = "c:\\logs\\journey.log";
		try {
			filename = "c:\\logs\\journey"
					+ URLEncoder.encode(sdf.format(cal.getTime()), "UTF-8")
					+ ".log";
		} catch (UnsupportedEncodingException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}

		File file = new File(filename);

		FileWriter fstream = null;
		try {
			fstream = new FileWriter(file, true);
			outFile = new BufferedWriter(fstream);
		} catch (IOException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}

	}

	// construim metoda ajutatoare pentru citirea de la client,
	// care sa afiseze automat in consola datele si sa le salveze in fisierul de log
	private String readInput() throws IOException {
		String input = in.readLine();
		if (outFile != null)
			outFile.write("Client: " + input + "\r\n");
		if (debug) {
			System.out.println("Client: " + input);
		}
		return input;
	}

	// construim metoda ajutatoarea pentru scrierea raspunsurilor catre client,
	// care sa se afiseze automat in consola si sa le salveze in fisierul de log
	private void writeOutput(String message) {
		out.println(message);
		try {
			if (outFile != null)
				outFile.write("Server: " + message + "\r\n");
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		if (debug) {
			System.out.println("Server: " + message);
		}
	}

	@Override
	public void run() {

		try {
			db = new DBManager();

			String nextLine = null;

			// read the first line.
			nextLine = readInput();
			if (nextLine == null)
				return;

			// exist if it doesn't start with authentication
			if (nextLine.startsWith("#auth-request#")) {
				nextLine = nextLine.replace("#auth-request#", "");

				// impartim textul dupa #
				StringTokenizer st = new StringTokenizer(nextLine, "#");
				String ticket = st.nextToken();
				BigInteger b = new BigInteger(st.nextToken());

				// validate ticket
				Statement statement = null;
				try {
					statement = (Statement) db.getConn().createStatement();
				} catch (SQLException e) {
					e.printStackTrace();
					writeOutput("Eroare conectare db");
					return;
				}

				// if ticket exists, sign and auth
				try {
					// daca ticketul exista si nu a mai fost folosit
					if (statement.executeQuery(
							"SELECT * FROM ticket WHERE name='" + ticket
									+ "' AND validated_at is null").next()) {
						// daca ticketul exista, marcam data de folosinta ca fiind data curenta
						statement
								.execute("UPDATE ticket SET validated_at = now() WHERE name='"
										+ ticket + "'");
						// sign b and send response
						writeOutput("#auth-validated#"
								+ BlindSignatureUtils.computeBlindSigned(b));
					} else {
						writeOutput("Ticketul este invalid");
						return;
					}
				} catch (SQLException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
					writeOutput("Eroare conectare db");
					return;
				}

				nextLine = readInput();
			}

			if (!nextLine.startsWith("#s#"))
				return;

			nextLine = nextLine.replace("#s#", "");

			StringTokenizer st = new StringTokenizer(nextLine, "#");

			String name = st.nextToken();
			String id_user = st.nextToken();
			String username = st.nextToken();

			CryptTool ct = new CryptTool();
			String current_token = st.nextToken();
			String password = current_token.equals("0") ? "" : ct
					.decrypt(current_token);
			current_token = st.nextToken();
			String staticId = current_token.equals("0") ? "" : ct
					.decrypt(current_token);
			
			BigInteger s = new BigInteger(st.nextToken());
			// verificam daca semnatura este valida
			if (BlindSignatureUtils.verifyBlind(
					BlindSignatureUtils.hash(staticId), s)) {
				writeOutput("ACK");
			} else {
				writeOutput("signature is invalid");
				return;
			}

			// System.out.println("line1: " + nextLine);

			try {
				Statement statement = (Statement) db.getConn()
						.createStatement();

				ResultSet rs = null;
				rs = statement
						.executeQuery("SELECT * FROM location WHERE id_user='"
								+ id_user + "'");
				if (!rs.next())
					db.doQuery("INSERT INTO location "
							+ "(id_user, name, lat, lng, speed, timestamp, stop) "
							+ "VALUES " + "('" + id_user + "', '" + name
							+ "', '', '', '', '', 0)");
				else {
					db.doQuery("UPDATE location SET " + "name = '" + name
							+ "' " + "WHERE id_user='" + id_user + "'");
				}
				rs = statement.executeQuery("SELECT * FROM users WHERE uuid='"
						+ staticId + "'");
				if (!rs.next()) {
					db.doPreparedQuery("INSERT INTO users "
							+ "(username, password, name, uuid) " + "VALUES "
							+ "(?, ?, ?, ?)", new String[] { username,
							password, name, staticId });
				} else
					db.doPreparedQuery("UPDATE users SET " + "username = ?, "
							+ "password = ?, " + "name = ? " + "WHERE uuid='"
							+ staticId + "'", new String[] { username,
							password, name });

				db.doQuery("INSERT INTO history " + "(id_user, file) "
						+ "VALUES " + "('" + staticId + "', '" + filename
						+ "')");
			} catch (SQLException e) {
				e.printStackTrace();
			}

			// receive data and write it to file.
			nextLine = readInput();
			while (nextLine != null && !nextLine.equals("#f#")) {
				StringTokenizer pos = new StringTokenizer(nextLine, " ");
				String lat, lng, speed, timestamp;
				lat = pos.nextToken();
				lng = pos.nextToken();
				speed = pos.nextToken();
				timestamp = pos.nextToken();

				db.doQuery("UPDATE `location` SET " + "`lat`='" + lat + "', "
						+ "`lng`='" + lng + "', " + "`speed`='" + speed + "', "
						+ "`timestamp`='" + timestamp + "' "
						+ "WHERE id_user='" + id_user + "'");

				nextLine = readInput();
			}

			out.close();
			in.close();
			outFile.close();
		} catch (IOException e) {
			e.printStackTrace();
			System.err.println("Server error. Please restart.");
			return;
		}
	}
}

public class TrafficCollectorServer {

	private static BigInteger s;

	/**
	 * Main method.
	 * 
	 * @param args
	 *            array of command line arguments
	 */
	public static void main(String args[]) {
		ServerSocket serverSocket;
		boolean debug = false;

		try {
			// create server socket on the 8082 port.
			serverSocket = new ServerSocket(8082);

			// set debug value.
			if (args.length == 1 && args[0].equals("-v"))
				debug = true;

			while (true) {
				Socket clientSocket = serverSocket.accept();
				Thread connectionThread = new ConnectionThread(clientSocket,
						debug);
				new Thread(connectionThread).start();
			}
		} catch (IOException e) {
			e.printStackTrace();
			System.err.println("Server error. Please restart.");
		}
	}

}