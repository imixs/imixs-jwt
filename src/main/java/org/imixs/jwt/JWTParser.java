/*******************************************************************************
 * <pre>
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
 *      http://www.imixs.org
 *      http://java.net/projects/imixs-workflow
 *  
 *  Contributors:  
 *      Imixs Software Solutions GmbH - initial API and implementation
 *      Ralph Soika - Software Developer
 * </pre>
 *******************************************************************************/

package org.imixs.jwt;

import javax.crypto.SecretKey;

/**
 * The JWTParser is used to verify a JWT and extract the header and payload part of the token.
 * 
 * @author rsoika
 *
 */
public class JWTParser {

  SecretKey key;
  String token;
  String header;
  String payload;
  String signature;

  public JWTParser setKey(SecretKey key) {
    this.key = key;
    return this;
  }

  public JWTParser setToken(String token) {
    this.token = token;
    return this;
  }

  /**
   * Verifies a token and decodes the payload and header in JSON format.
   * 
   * @return payload
   * @throws JWTException
   */
  public JWTParser verify() throws JWTException {

    if (key == null) {
      throw new JWTException("MISSING_SECRET_KEY", "No SecretKey defined!");
    }

    if (token == null || token.isEmpty()) {
      throw new JWTException("MISSING_TOKEN", "Token is empty!");
    }

    // split token
    String[] parts = token.split("\\.");

    if (parts == null || parts.length < 3) {
      throw new JWTException("INVALID_TOKEN", "Token is invalid!");
    }

    String encodedHeader = parts[0];
    String encodedPayload = parts[1];
    signature = parts[2];

    // create and validate signatore
    JWTBuilder _builder = new JWTBuilder();
    String _signature = _builder.setKey(key).setEncodedHeader(encodedHeader)
        .setEncodedPayload(encodedPayload).sign().getSignature();

    if (!_signature.equals(signature)) {
      throw new JWTException("INVALID_SIGNATURE", "Signature is invalid!");
    }

    // update header and payload
    this.header = HMAC.decodeBase64(encodedHeader.getBytes());
    this.payload = HMAC.decodeBase64(encodedPayload.getBytes());

    return this;
  }

  /**
   * Returns the decoded header in JSON format
   * 
   * @return
   */
  public String getHeader() {
    return this.header;
  }

  /**
   * Returns the decoded header in JSON format
   * 
   * @return
   */
  public String getPayload() {
    return this.payload;
  }

}
