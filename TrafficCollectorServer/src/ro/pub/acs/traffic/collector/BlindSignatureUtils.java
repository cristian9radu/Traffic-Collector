package ro.pub.acs.traffic.collector;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import org.apache.commons.codec.binary.Base64;

public class BlindSignatureUtils {
	static String private_key = "MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAL6YAfPMA5PIN4upUZFtJ79izZ0DQrQ9jOztWSFRxJzMkRyQsSrONVZqmZDtdJec42c44DstXNgu+9Fz/d3QQreCrWwXf0kwpSl5poj44C4TdRVEsjGeaYwkFOQAapJC46G4buomy0MKDj1bcp4xzxldeDtPhONFavceD1Vsf5EjAgMBAAECgYBV56fBnivimTTIA0oblSp8LellIsoW+UMiqxwoU3WeAupJCMKB+624xJVw6EZL68/nf5A5vAmD+zFPR8ueBbd7vPLYvrh7He8tZXzL4sTMTL+0QVgjoA7TNkCdG92t0AL2M8+euYdtJpL/YZSn9j91IYDejp5Oy1tPobZOjakYKQJBAPWJq1yP9QUOVrBi26VuXckcuN+tGDgdDQsnn2Vr6f1uAxe628xeNakfB1txfdVnUWXzSeaDVE5XS0C9sQ8JTJUCQQDGtwIWjiTbL/mddBf2YugZ6qs7wVg/VsXKFs/l6O7jgzT1f30yUyItotVYmg9BDN28y4f8jfg7QV601pNIn0DXAkAsw4iGO4iD/3U2ew9oPZLDk4Tw4nHD6SfznKmmp+Hk3iWaMerYe2R1DL8eoLY8LbXdTFlwuQipr6h8iRi6kQtxAkAzqsHQO4U5uG+ekODqHy1aD7oV/1+CmH003lmP3dC/Nw4+Brf2rcblNsFiGCx/LWk5/XGOKRuxzH1jZ6dD6qRhAkEAy98xudB+y2DrzPfFJU6iNjPz/wJm3H+tZ84OFvgf1yU/JKkeG5Mx5pcy6AEutVt5fWN+ctPsjf4IePXTVLjCTQ==";

	static String public_key = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC+mAHzzAOTyDeLqVGRbSe/Ys2dA0K0PYzs7VkhUcSczJEckLEqzjVWapmQ7XSXnONnOOA7LVzYLvvRc/3d0EK3gq1sF39JMKUpeaaI+OAuE3UVRLIxnmmMJBTkAGqSQuOhuG7qJstDCg49W3KeMc8ZXXg7T4TjRWr3Hg9VbH+RIwIDAQAB";
	
	public static final String ALGORITHM = "RSA/ECB/PKCS1PADDING";

	public static PublicKey getPublicKey(String key) {
		try {
			Base64 base64_decoder = new Base64();
			byte[] byteKey = base64_decoder.decode(key.getBytes()); // ,
																	// Base64.DEFAULT);
			X509EncodedKeySpec X509publicKey = new X509EncodedKeySpec(byteKey);
			KeyFactory kf = KeyFactory.getInstance("RSA");

			return kf.generatePublic(X509publicKey);
		} catch (Exception e) {
			e.printStackTrace();
		}

		return null;
	}

	public static PrivateKey getPrivateKey(String key) {
		try {
			Base64 base64_decoder = new Base64();
			byte[] byteKey = base64_decoder.decode(key.getBytes()); // ,
																	// Base64.DEFAULT);
			PKCS8EncodedKeySpec X509privateKey = new PKCS8EncodedKeySpec(
					byteKey);
			KeyFactory kf = KeyFactory.getInstance("RSA");

			return kf.generatePrivate(X509privateKey);
		} catch (Exception e) {
			e.printStackTrace();
		}

		return null;
	}

	public static byte[] hash(String message) {
		MessageDigest cript = null;
		try {
			cript = MessageDigest.getInstance("SHA-1");
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return null;
		}
		cript.reset();
		try {
			cript.update(message.getBytes("utf8"));
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
			return null;
		}
		return cript.digest();
	}

	// client
	public static BlindResult computeBlind(byte[] message)
			throws NoSuchAlgorithmException, NoSuchProviderException,
			UnsupportedEncodingException {
		BigInteger m = new BigInteger(message);
		RSAPublicKey pubKey = (RSAPublicKey) getPublicKey(public_key);

		BigInteger e = pubKey.getPublicExponent();

		SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
		byte[] randomBytes = new byte[10];
		BigInteger r = null;
		BigInteger n = pubKey.getModulus();
		BigInteger gcd = null;
		BigInteger one = new BigInteger("1");
		// check that gcd(r,n) = 1 && r < n && r > 1
		do {
			random.nextBytes(randomBytes);
			r = new BigInteger(1, randomBytes);
			gcd = r.gcd(n);
		} while (!gcd.equals(one) || r.compareTo(n) >= 0
				|| r.compareTo(one) <= 0);

		// ********************* BLIND ************************************

		BigInteger b = ((r.modPow(e, n)).multiply(m)).mod(n);

		BlindResult result = new BlindResult();
		result.setBlind(b);
		result.setRandom(r);

		return result;
	}

	// server
	public static BigInteger computeBlindSigned(BigInteger b) {
		RSAPublicKey pubKey = (RSAPublicKey) getPublicKey(public_key);
		RSAPrivateKey privKey = (RSAPrivateKey) getPrivateKey(private_key);

		BigInteger d = privKey.getPrivateExponent();
		BigInteger n = pubKey.getModulus();

		BigInteger bs = b.modPow(d, n);
		return bs;
	}

	// server
	public static boolean verifyBlind(byte[] message, BigInteger s)
			throws UnsupportedEncodingException {
		BigInteger m = new BigInteger(message);

		RSAPublicKey pubKey = (RSAPublicKey) getPublicKey(public_key);
		RSAPrivateKey privKey = (RSAPrivateKey) getPrivateKey(private_key);

		BigInteger d = privKey.getPrivateExponent();
		BigInteger n = pubKey.getModulus();

		// signature of m should = (m^d) mod n
		BigInteger sig_of_m = m.modPow(d, n);

		return s.equals(sig_of_m);
	}

	// client
	public static BigInteger computeUnblindSignature(BigInteger r, BigInteger bs)
			throws UnsupportedEncodingException {
		RSAPublicKey pubKey = (RSAPublicKey) getPublicKey(public_key);
		BigInteger n = pubKey.getModulus();

		BigInteger s = r.modInverse(n).multiply(bs).mod(n);

		return s;
	}

	// client
	public static boolean verifyBlindRSA(byte[] message, BigInteger r,
			BigInteger bs) throws UnsupportedEncodingException {
		// try to verify using the RSA formula
		BigInteger m = new BigInteger(message);

		RSAPublicKey pubKey = (RSAPublicKey) getPublicKey(public_key);

		BigInteger e = pubKey.getPublicExponent();
		BigInteger n = pubKey.getModulus();

		BigInteger s = r.modInverse(n).multiply(bs).mod(n);

		BigInteger check = s.modPow(e, n);
		return m.equals(check);
	}
}
