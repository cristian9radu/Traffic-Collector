package ro.pub.acs.traffic.utils;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESedeKeySpec;
import javax.crypto.spec.IvParameterSpec;
import android.util.*;

public class CryptTool {
	private static final String SHARED_KEY = "XtHVMwLjtxq5ilOpSGHmc2PSvoQ9W0wv9taPREsj";
	private static String algorithm = "DESede";
	private static String transformation = "DESede/CBC/PKCS5Padding";
	private SecretKey key;
	private IvParameterSpec iv;
	
	public CryptTool(){
		DESedeKeySpec keySpec;
		byte[] keyValue = SHARED_KEY.getBytes();
		
		try {
			keySpec = new DESedeKeySpec(keyValue);
			/* Initialization Vector of 8 bytes set to zero. */
	        iv = new IvParameterSpec(new byte[8]);

	        key = SecretKeyFactory.getInstance(algorithm).generateSecret(keySpec);
	    } catch (Exception e) {
			e.printStackTrace();
		}	
	}
	
	public String encrypt(String str) {
		String encryptedString = null;
        
		try {
	        Cipher encrypter = Cipher.getInstance(transformation);
	        encrypter.init(Cipher.ENCRYPT_MODE, key, iv);
	        byte[] input = str.getBytes("UTF-8");
	        byte[] encrypted = encrypter.doFinal(input);
            encryptedString = Base64.encodeToString(encrypted, Base64.NO_WRAP);
		} catch (Exception e) {
			e.printStackTrace();
		}

        return encryptedString;
	}
	
	public String decrypt(String encryptedString) {
		String decryptedText=null;
		try {
			Cipher decrypter = Cipher.getInstance(transformation);
	        decrypter.init(Cipher.DECRYPT_MODE, key, iv);
	        
	        byte[] encryptedText = Base64.decode(encryptedString, Base64.NO_WRAP);
	        byte[] plainText = decrypter.doFinal(encryptedText);
	        decryptedText= bytes2String(plainText);
		} catch (Exception e) {
			e.printStackTrace();
		}
		return decryptedText;
	}
	
	/**
     * Returns String From An Array Of Bytes
     */
    public static String bytes2String(byte[] bytes) {
        StringBuffer stringBuffer = new StringBuffer();
        for (int i = 0; i < bytes.length; i++) {
            stringBuffer.append((char) bytes[i]);
        }
        return stringBuffer.toString();
    }
    
    /**
     * Testing The DESede Encryption And Decryption Technique
     */
    public static void main(String args []) throws Exception
    {
        CryptTool myEncryptor= new CryptTool();
 
        String stringToEncrypt="bitbestebita";
        String encrypted = myEncryptor.encrypt(stringToEncrypt);
        String decrypted = myEncryptor.decrypt(encrypted);
 
        System.out.println("String To Encrypt: "+stringToEncrypt);
        System.out.println("Encrypted Value :" + encrypted);
        System.out.println("Decrypted Value :"+decrypted);
 
    }
}