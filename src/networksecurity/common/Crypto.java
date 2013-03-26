package networksecurity.common;

import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Random;

public class Crypto{
	
	public static final String CHARSET = "UTF-8";
	private static final String RSA_CIPHER = "RSA";
	private static final String SHA1 = "SHA1";
	
	/**
	 * Generate the validation hash for a given password.
	 * 
	 * @param password The password to generate a validation hash for.
	 * 
	 * @return The validation hash for the given password.
	 */
	public static String generateValidationHash(String password) {
		final Random rand = new Random(password.hashCode());
		
		// not that we convert everything to a hex string just to make
		// the config file easy writing easy
		try {
			return String.format(
				"%x", 
				new BigInteger(hash(String.valueOf(rand.nextLong())).getBytes(Crypto.CHARSET))
			);
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
			throw new IllegalStateException(e);
		}
	}

	/**
	 * Hash the given value using the SHA-1 hash function.
	 * 
	 * @param value The value to hash.
	 * 
	 * @return The hashed version of value.
	 */
	public static String hash(String value) {
		try {
			MessageDigest sha1 = MessageDigest.getInstance(SHA1);

			return new String(sha1.digest(value.getBytes(Crypto.CHARSET)), Crypto.CHARSET);
		} catch (Exception e) {
			throw new IllegalStateException(e);
		}
	}
	
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