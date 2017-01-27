package org.imixs.jwt;

import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.util.logging.Logger;

import javax.crypto.SecretKey;

import org.imixs.jwt.HMAC;
import org.junit.Before;
import org.junit.Test;

import junit.framework.Assert;

/**
 * Test HMAC class. Signing token
 * 
 * @author rsoika
 * 
 */
public class HMACTest {

	private static Logger logger = Logger.getLogger(HMACTest.class.getName());
	String header;
	String payload;
	String encodedHeader;
	String encodedPayload;
	String secret;
	String algorithm; // "HmacMD5"

	@Before
	public void setup() {
		header = "{\"alg\":\"HS256\",\"typ\":\"JWT\"}";
		payload = "{\"sub\":\"1234567890\",\"name\":\"John Doe\",\"admin\":true}";

		encodedHeader = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
		encodedPayload = "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9";
		secret = "secret";
		algorithm = "HmacSHA256";
	}

	/**
	 * test HMAC Base64 encoding
	 */
	@Test
	public void testBase64Encoding() {
		Assert.assertEquals(encodedHeader, HMAC.encodeBase64(header.getBytes()));
		Assert.assertEquals(encodedPayload, HMAC.encodeBase64(payload.getBytes()));
	}

	/**
	 * test HMAC Base64 decoding
	 */
	@Test
	public void testBase64Decoding() {
		Assert.assertEquals(header, HMAC.decodeBase64(encodedHeader.getBytes()));
		Assert.assertEquals(payload, HMAC.decodeBase64(encodedPayload.getBytes()));
	}

	/**
	 * Test signatrue based on the iwt.io debugger example
	 * 
	 * https://jwt.io/
	 * 
	 * @throws InvalidKeyException
	 * @throws SignatureException
	 * @throws NoSuchAlgorithmException
	 * @throws IllegalStateException
	 * @throws UnsupportedEncodingException
	 */
	@Test
	public void testSignatureWithEncodedData() throws InvalidKeyException, SignatureException, NoSuchAlgorithmException,
			IllegalStateException, UnsupportedEncodingException {

		SecretKey secretKey = HMAC.createKey(algorithm, secret.getBytes());

		logger.info("algorithm=" + secretKey.getAlgorithm());
		logger.info("key=" + HMAC.encodeBase64(secretKey.getEncoded()));
		String message = encodedHeader + "." + encodedPayload;
		byte[] signature = HMAC.createSignature(secretKey, message.getBytes());

		logger.info("signature=" + HMAC.encodeBase64(signature));
		Assert.assertEquals("TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ", HMAC.encodeBase64(signature));
	}

}
