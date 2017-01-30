/*******************************************************************************
 *  Imixs Workflow 
 *  Copyright (C) 2001, 2011 Imixs Software Solutions GmbH,  
 *  http://www.imixs.com
 *  
 *  This program is free software; you can redistribute it and/or 
 *  modify it under the terms of the GNU General Public License 
 *  as published by the Free Software Foundation; either version 2 
 *  of the License, or (at your option) any later version.
 *  
 *  This program is distributed in the hope that it will be useful, 
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of 
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU 
 *  General Public License for more details.
 *  
 *  You can receive a copy of the GNU General Public
 *  License at http://www.gnu.org/licenses/gpl.html
 *  
 *  Project: 
 *  	http://www.imixs.org
 *  	http://java.net/projects/imixs-workflow
 *  
 *  Contributors:  
 *  	Imixs Software Solutions GmbH - initial API and implementation
 *  	Ralph Soika - Software Developer
 *******************************************************************************/

package org.imixs.jwt;

import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.util.logging.Logger;

import javax.crypto.SecretKey;

import org.junit.Before;
import org.junit.Test;

import junit.framework.Assert;

/**
 * Test JWTParser class. Verify a token
 * 
 * @author rsoika
 * 
 */
public class JWTParserTest {

	private static Logger logger = Logger.getLogger(JWTParserTest.class.getName());

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
	public void testVerify() throws JWTException {

		SecretKey secretKey = HMAC.createKey(algorithm, secret.getBytes());

		String _payload = new JWTParser().setKey(secretKey).setToken(token).verify().getPayload();

		logger.info("payload=" + _payload);

		Assert.assertEquals(payload, _payload);

	}

	/**
	 * Test a corrupted signature with encoded data, based on the iwt.io
	 * debugger example
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
	@SuppressWarnings("unused")
	@Test
	public void testVerifyInvalidData() {

		SecretKey secretKey = HMAC.createKey(algorithm, secret.getBytes());

		try {
			String _payload = new JWTParser().setKey(secretKey).setToken(token + "x").verify().getPayload();
			Assert.fail();
		} catch (JWTException e) {
			// expected invalid signature
			Assert.assertEquals("INVALID_SIGNATURE", e.errorCode);
		}

	}

}
