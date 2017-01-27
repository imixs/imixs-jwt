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

/**
 * JSON Web Signature (JWS) algorithm names, represents in the JWA RFC
 * (https://tools.ietf.org/html/rfc7518)
 * 
 * @author Ralph Soika
 * @version 1.0.0
 */
public final class JWSAlgorithm {

	/**
	 * HMAC using SHA-256 hash algorithm (required).
	 */
	public static final String JWA_HS256 = "HS256";
	public static final String JDK_HS256 = "HmacSHA256";

	/**
	 * HMAC using SHA-384 hash algorithm (optional).
	 */
	public static final String JWA_HS384 = "HS384";
	public static final String JDK_HS384 = "HmacSHA384";

	/**
	 * HMAC using SHA-512 hash algorithm (required).
	 */
	public static final String JWA_HS512 = "HS512";
	public static final String JDK_HS512 = "HmacSHA512";

	
	/**
	 * Returns the JSON Web Algorithm name for a given Java MAC algorithm. 
	 * @param jdk_algorithm
	 * @return jwa
	 */
	public static String getJWA(String jdk_algorithm) {
		if (jdk_algorithm.equals(JDK_HS256))
			return JWA_HS256;
		
		if (jdk_algorithm.equals(JDK_HS384))
			return JWA_HS384;
		
		if (jdk_algorithm.equals(JDK_HS512))
			return JWA_HS512;
		
		return "none";
	}
}
