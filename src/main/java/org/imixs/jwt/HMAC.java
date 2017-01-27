package org.imixs.jwt;

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 * HMAC provides static methods to generate SecretKeySpec and Hash-based Message
 * Authentication Codes (HMAC). This class is thread-safe.
 *
 * @author Ralph Soika
 * @version 1.0.0
 */

public class HMAC {

	/**
	 * Computes a Hash-based Message Authentication Code (HMAC) for the
	 * specified secret key and message.
	 *
	 * @param secretKey
	 *            The secret key, with the appropriate HMAC algorithm. Must not
	 *            be {@code null}.
	 * @param message
	 *            The message. Must not be {@code null}.
	 * @return A MAC service instance.
	 */
	public static byte[] createSignature(final SecretKey secretKey, final byte[] message)
			throws InvalidKeyException, NoSuchAlgorithmException {

		Mac mac;
		mac = Mac.getInstance(secretKey.getAlgorithm());
		mac.init(secretKey);
		mac.update(message);
		return mac.doFinal();
	}

	/**
	 * generates a key
	 * 
	 * @param alg
	 * @param secret
	 * @return
	 */
	public static SecretKey createKey(final String alg, final byte[] secret) {
		return new SecretKeySpec(secret, alg);
	}
	
	
	/**
	 * Base64 encoding without padding 
	 * 
	 * @param data
	 * @return encoded data
	 */
	public static String encodeBase64(byte[] data) {
		byte[] encoded = Base64.getEncoder().withoutPadding().encode(data);

		return new String(encoded, StandardCharsets.UTF_8);

	}
	
	/**
	 * Base64 encoding without padding 
	 * 
	 * @param data
	 * @return decoded data
	 */
	public static String decodeBase64(byte[] data) {
		
		byte[] decoded=Base64.getDecoder().decode(data);
		return new String(decoded, StandardCharsets.UTF_8);
	}

}
