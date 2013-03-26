package networksecurity.common;

import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class Crypto{
	
	private static final String RSA_CIPHER = "RSA";
	
	/**
	 * Read a private key in from the file at the given location.
	 * 
	 * @param filename The location of the private key.
	 * 
	 * @return The private key.
	 * 
	 * @throws Exception Thrown for all errors.
	 */
	public static PrivateKey readPrivateKey(String filename)
	    throws Exception
	{
		File f = new File(filename);
		FileInputStream fis = new FileInputStream(f);
		DataInputStream dis = new DataInputStream(fis);

		int len = dis.readInt();
		byte[] keyBytes = new byte[len];
		dis.readFully(keyBytes);
		dis.close();

		PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
		KeyFactory kf = KeyFactory.getInstance(RSA_CIPHER);
		System.out.println("RSA Private key loaded from " + f.getPath());
		return kf.generatePrivate(spec);
	}
	
	/**
	 * Read a public key in from the file at the given location.
	 * 
	 * @param filename The location of the public key.
	 * 
	 * @return The public key.
	 * 
	 * @throws Exception Thrown for all errors.
	 */
	public static PublicKey readPublicKey(String filename)
	    throws Exception{
		
		File f = new File(filename);
		FileInputStream fis = new FileInputStream(f);
		DataInputStream dis = new DataInputStream(fis);

		int len = dis.readInt();
		byte[] keyBytes = new byte[len];
		dis.readFully(keyBytes);
		dis.close();

		X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
		KeyFactory kf = KeyFactory.getInstance(RSA_CIPHER);
		System.out.println("RSA Public key loaded from " + f.getPath());
		return kf.generatePublic(spec);
	}

}