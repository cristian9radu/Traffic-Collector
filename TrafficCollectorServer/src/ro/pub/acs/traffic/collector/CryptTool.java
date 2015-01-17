package ro.pub.acs.traffic.collector;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESedeKeySpec;
import javax.crypto.spec.IvParameterSpec;

import org.apache.commons.codec.binary.Base64;

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
            encryptedString = Base64.encodeBase64String(encrypted);
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
	        
	        byte[] encryptedText = Base64.decodeBase64(encryptedString);
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
    private static String bytes2String(byte[] bytes) {
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
		if(Integer.parseInt(args[0]) == 0)
		{
			String stringToEncrypt = args[1];
			String encrypted = myEncryptor.encrypt(stringToEncrypt);
			System.out.println(encrypted);
		}
		else if(Integer.parseInt(args[0]) == 1)
		{
			String stringToDecrypt = args[1];
			String decrypted = myEncryptor.decrypt(stringToDecrypt);
			System.out.println(decrypted);
		}
    }
}