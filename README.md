# Imixs-JWT

Imixs-JWT is a compact easy to use library to generate and verify JSON Web Tokens.


##Installation

Imixs-JWT is based on maven. Add the following dependency available from Maven Central:

	<dependency>
	     <groupId>org.imixs.jwt</groupId>
	     <artifactId>imixs-jwt</artifactId>
	     <version>0.0.1-SNAPSHOT</version>
	</dependency>

## Quickstart

Imixs-JWT makes it easy to create and verify JSON Web Tokens.  Here's an example:

	import org.imixs.jwt.*;
	import java.security.InvalidKeyException;
	import java.security.NoSuchAlgorithmException;
	import javax.crypto.SecretKey;
	
	...
	// We need a signing key
	SecretKey secretKey = HMAC.createKey("HmacSHA256", "secret".getBytes());
	// JSON Payload
	String payload="{\"sub\":\"1234567890\",\"name\":\"John Doe\",\"admin\":true}";
	JWTBuilder builder = new JWTBuilder().setKey(secretKey).setJSONPayload(payload);
	System.out.println("JWT=" + builder.getToken());
	
	// will result in:
	// eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.
	// eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.
	// TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ



That's it!
  
