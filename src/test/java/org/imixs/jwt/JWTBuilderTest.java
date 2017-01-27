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
 * Test JWTBuilder class. Signing token
 * 
 * @author rsoika
 * 
 */
public class JWTBuilderTest {

	private static Logger logger = Logger.getLogger(JWTBuilderTest.class.getName());

	String header;
	String payload;
	String encodedHeader;
	String encodedPayload;
	String secret;
	String algorithm; // "HmacMD5"
	String signature;
	String token;

	/**
	 * Data based on iwt.io debugger example
	 */
	@Before
	public void setup() {
		header = "{\"alg\":\"HS256\",\"typ\":\"JWT\"}";
		payload = "{\"sub\":\"1234567890\",\"name\":\"John Doe\",\"admin\":true}";
		encodedHeader = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
		encodedPayload = "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9";
		secret = "secret";
		algorithm = "HmacSHA256";
		signature = "TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ";// expected
																	// base64
																	// encoded
																	// signature

		token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ";
	}

	/**
	 * Test signature with encoded data, based on the iwt.io debugger example
	 * 
	 * https://jwt.io/
	 * 
	 * @throws JWTException
	 * 
	 * @throws InvalidKeyException
	 * @throws SignatureException
	 * @throws NoSuchAlgorithmException
	 * @throws IllegalStateException
	 * @throws UnsupportedEncodingException
	 */
	@Test
	public void testSignatureEncoded() throws JWTException {

		SecretKey secretKey = HMAC.createKey(algorithm, secret.getBytes());

		JWTBuilder builder = new JWTBuilder().setKey(secretKey).setEncodedHeader(encodedHeader)
				.setEncodedPayload(encodedPayload).sign();

		logger.info("signature=" + builder.getSignature());
		Assert.assertEquals(signature, builder.getSignature());

		logger.info("header=" + HMAC.decodeBase64(encodedPayload.getBytes()));
	}

	/**
	 * Test signature with JSON data, based on the iwt.io debugger example
	 * 
	 * https://jwt.io/
	 * 
	 * @throws JWTException
	 * 
	 * @throws InvalidKeyException
	 * @throws SignatureException
	 * @throws NoSuchAlgorithmException
	 * @throws IllegalStateException
	 * @throws UnsupportedEncodingException
	 */
	@Test
	public void testSignatureJSON() throws JWTException {

		SecretKey secretKey = HMAC.createKey(algorithm, secret.getBytes());

		JWTBuilder builder = new JWTBuilder().setKey(secretKey).setJSONHeader(header).setJSONPayload(payload).sign();

		logger.info("signature=" + builder.getSignature());
		Assert.assertEquals(signature, builder.getSignature());

		
	}

	/**
	 * Test JSON Web token, based on the iwt.io debugger example
	 * 
	 * https://jwt.io/
	 * 
	 * @throws JWTException
	 * 
	 * @throws InvalidKeyException
	 * @throws SignatureException
	 * @throws NoSuchAlgorithmException
	 * @throws IllegalStateException
	 * @throws UnsupportedEncodingException
	 */
	@Test
	public void testJSONWebToken() throws JWTException {

		SecretKey secretKey = HMAC.createKey(algorithm, secret.getBytes());

		JWTBuilder builder = new JWTBuilder().setKey(secretKey).setJSONHeader(header).setJSONPayload(payload).sign();

		logger.info("JWT=" + builder.getToken());
		Assert.assertEquals(token, builder.getToken());

		
		// test short form
		builder = new JWTBuilder().setKey(secretKey).setJSONPayload(payload);

		logger.info("JWT=" + builder.getToken());
		Assert.assertEquals(token, builder.getToken());

	
	}

}
