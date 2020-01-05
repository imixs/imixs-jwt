/*******************************************************************************
 * Imixs Workflow Copyright (C) 2001, 2011 Imixs Software Solutions GmbH, http://www.imixs.com
 * 
 * This program is free software; you can redistribute it and/or modify it under the terms of the
 * GNU General Public License as published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without
 * even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 * 
 * You can receive a copy of the GNU General Public License at http://www.gnu.org/licenses/gpl.html
 * 
 * Project: http://www.imixs.org http://java.net/projects/imixs-workflow
 * 
 * Contributors: Imixs Software Solutions GmbH - initial API and implementation Ralph Soika -
 * Software Developer
 *******************************************************************************/

package org.imixs.jwt;

import java.io.StringReader;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.util.Date;
import java.util.logging.Logger;
import javax.crypto.SecretKey;
import javax.json.Json;
import javax.json.JsonObject;
import javax.json.JsonReader;
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
  String payload_without_iat;
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
    payload = "{\"iat\":1578218678992,\"sub\":\"1234567890\",\"name\":\"John Doe\",\"admin\":true}";
    payload_without_iat = "{\"sub\":\"1234567890\",\"name\":\"John Doe\",\"admin\":true}";
    encodedHeader = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
    encodedPayload = "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9";
    secret = "secret";
    algorithm = "HmacSHA256";
    signature = "P0tXidx2nGdGhmJ9+0bcNqDbM5zU+WKGib0u5osG7Gc";// expected
                                                              // base64
                                                              // encoded
                                                              // signature

    // token =
    // "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOiIxMjMiLCJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.P0tXidx2nGdGhmJ9+0bcNqDbM5zU+WKGib0u5osG7Gc";
    token =
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE1NzgyMTg2Nzg5OTIsInN1YiI6IjEyMzQ1Njc4OTAiLCJuYW1lIjoiSm9obiBEb2UiLCJhZG1pbiI6dHJ1ZX0.ujX9a3mbNIq2+z3/5tam0UujZCSaJQKYe43av2xnIzI";
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

    logger.info("header=" + HMAC.decodeBase64(encodedHeader.getBytes()));
    logger.info("payload=" + HMAC.decodeBase64(encodedPayload.getBytes()));
    logger.info("signature=" + builder.getSignature());
    Assert.assertEquals("TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ", builder.getSignature());

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

    JWTBuilder builder =
        new JWTBuilder().setKey(secretKey).setHeader(header).setPayload(payload).sign();

    logger.info("signature=" + builder.getSignature());
    Assert.assertEquals("ujX9a3mbNIq2+z3/5tam0UujZCSaJQKYe43av2xnIzI", builder.getSignature());


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

    JWTBuilder builder =
        new JWTBuilder().setKey(secretKey).setHeader(header).setPayload(payload).sign();

    logger.info("JWT=" + builder.getToken());
    Assert.assertEquals(token, builder.getToken());


    // test short form
    builder = new JWTBuilder().setKey(secretKey).setPayload(payload);

    logger.info("JWT=" + builder.getToken());
    Assert.assertEquals(token, builder.getToken());


  }



  /**
   * Test JSON Web token, with missing iat. Expectation : iat is created
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
  public void testJSONWebTokenWithIat() throws JWTException {

    SecretKey secretKey = HMAC.createKey(algorithm, secret.getBytes());

    JWTBuilder builder =
        new JWTBuilder().setKey(secretKey).setHeader(header).setPayload(payload_without_iat).sign();

    String iat_token = builder.getToken();
    logger.info("JWT=" + iat_token);

    // recalculate the payload and test if 'iat' is available...

    String iat_payload =
        new JWTParser().setKey(secretKey).setToken(iat_token).verify().getPayload();


    logger.info("Payload=" + iat_payload);

    // now parse the json .....
    JsonReader reader = Json.createReader(new StringReader(iat_payload));
    JsonObject payloadObject = reader.readObject();


    try {
      // get the iat.....
      long iat = payloadObject.getInt("iat");
      Date now = new Date();
      logger.info("iat=" + iat + " -> now=" + now.getTime());
      Assert.assertTrue(iat > 0 && iat <= now.getTime());
    } catch (NullPointerException e) {
      Assert.fail();
    }



  }

}
