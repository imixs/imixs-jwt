# Imixs-JWT

Imixs-JWT is a compact easy to use library to generate and verify JSON Web Tokens.
The project also provides a JASPIC authentication module to be used in Java EE application servers. 


## Installation

Imixs-JWT is based on maven. Add the following dependency available from Maven Central:

	<dependency>
	     <groupId>org.imixs.jwt</groupId>
	     <artifactId>imixs-jwt</artifactId>
	     <version>1.0.0</version>
	</dependency>

## Quickstart

Imixs-JWT makes it easy to create and verify JSON Web Tokens. 

## Build a JSON Web Token

The following example shows how to build a JWT:

	import org.imixs.jwt.*;
	import java.security.InvalidKeyException;
	import java.security.NoSuchAlgorithmException;
	import javax.crypto.SecretKey;
	
	...
	// We need a signing key...
	SecretKey secretKey = HMAC.createKey("HmacSHA256", "secret".getBytes());
	String payload="{\"sub\":\"1234567890\",\"name\":\"John Doe\",\"admin\":true}";
	JWTBuilder builder = new JWTBuilder().setKey(secretKey).setPayload(payload);
	System.out.println("JWT=" + builder.getToken());
	
	// will result in:
	// eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.
	// eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.
	// TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ



That's it!
  
## Verify a JSON Web Token

To verify and extract the payload of a JSON Web Token (as build in the example before) can be seen in the next example:
   
	import org.imixs.jwt.*;
	import java.security.InvalidKeyException;
	import java.security.NoSuchAlgorithmException;
	import javax.crypto.SecretKey;
	
	// given token:
	// eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.
	// eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.
	// TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ
	...
	// We need the secret key...
	SecretKey secretKey = HMAC.createKey("HmacSHA256", "secret".getBytes());
	try {
		// verify token and get the payload...
		String payload = new JWTParser().setKey(secretKey).setToken(token).verify().getPayload();
		// payload will result in:
		// {"sub":"1234567890","name":"John Doe","admin":true}
	} catch (JWTException e) {
			// invalid token!
	}

   
# JASPIC Auth Module

Imixs-JWT provides a JASPIC authentication module to be used in Java EE Application servers. 

The payload of the JSON Web Token is expected in the following format:

	{"sub":"admin","groups":["xxx","yyy"],"displayname":"Administrator"}

Where 'sub' is the principal and 'groups' provides an array of groupnames (roles) assigned to the principal. Additional user attributes (like email or a displayname) can be added as optional key-value pairs. 

With the TokenGenerator a JWT token can be generated from the command line:

	java -cp classes org.imixs.jwt.TokenGenerator secret {"sub":"admin","displayname":"Administrator","groups":["xxx","yyy"]}

**NOTE:** The JASPIC Auth Module accepts Json Web Tokens in a query string or as a bearer token provided in the request header: 

 - /...?jwt=xxxxx
 - HEADER jwt=xxxx
 - HEADER Authorization=Bearer xxxx
	

## Configuration for Wildfly 10

To install the AuthModule in a Wildfly 10 application server, the module must be part of the web application.
To activate the JASPIC module, the file *WEB-INF/jboss-web.xml* needs to be added, that references the corresponding JASPIC domain:


	<?xml version="1.0"?>
	<jboss-web>
	    <security-domain>imixs-jwt</security-domain>
	</jboss-web>

The security domain has be configured in the standalone.xml file. See the following example:

	<!-- imixs-jwt module  -->
    <security-domain name="imixs-jwt">
		<authentication-jaspi>
			<login-module-stack name="imixs-jwt-stack">
				 <login-module code="Dummy"  flag="optional"/>
			</login-module-stack>
			<auth-module code="org.imixs.jwt.jaspic.JWTAuthModule">
			 	<module-option name="secret" value="secret"/>
			</auth-module>
		</authentication-jaspi>
	</security-domain>

The module-option 'secret' contains the JWT password for decoding the token.


Find more information about JASPIC for Wildfly here:

- http://arjan-tijms.omnifaces.org/2015/08/activating-jaspic-in-jboss-wildfly.html
- https://developer.jboss.org/wiki/JBossAS7EnablingJASPIAuthenticationForWebApplications
- https://stackoverflow.com/questions/30033105/jaspic-module-not-propagating-principal-to-local-ejb-in-jboss-7-4
