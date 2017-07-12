package org.imixs.jwt;

import javax.crypto.SecretKey;

/**
 * This Java App can be used to generate a JWT Token
 * 
 * The application expects two parameters: password and payload token:
 * 
 *  <pre>
 *     java -cp classes org.imixs.jwt.TokenGenerator secret {"sub":"admin","displayname":"Administrator","groups":["xxx","yyy"]}
 *  </pre>
 *   
 * @author rsoika  
 *
 */
public class TokenGenerator {
	static String secret = "secret";
	public static void main(String[] args) throws JWTException {
		
		
		if (args==null || args.length<2){
			System.out.println("Missing parameters. Usage: java -cp classes org.imixs.jwt.TokenGenerator mypassword {\"sub\":\"admin\",\"displayname\":\"Administrator\",\"groups\":\"xxx,yyy\"}");
			return;
		}
		
		// get params
		secret=args[0];
		String payload=args[1];

		System.out.println("Payload=" + payload);
		
		// We need a signing key...
		SecretKey secretKey = HMAC.createKey(JWSAlgorithm.JDK_HS256, secret.getBytes());
	
		JWTBuilder builder = new JWTBuilder().setKey(secretKey).setHeader(JWTBuilder.DEFAULT_HEADER).setPayload(payload).sign();

		System.out.println("Token=" + builder.getToken());
		
	
		
	}

}
