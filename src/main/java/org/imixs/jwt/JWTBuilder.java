package org.imixs.jwt;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.SecretKey;

public class JWTBuilder {

	SecretKey key;
	String header;
	String payload;
	String signature;

	public JWTBuilder setKey(SecretKey key) {
		this.key = key;
		return this;
	}

	/**
	 * Set an base64 encoded header
	 * 
	 * @param header
	 * @return
	 */
	public JWTBuilder setEncodedHeader(String header) {
		this.header = header;
		return this;
	}

	/**
	 * Set a JSON header. The header will be base64 encoded.
	 * 
	 * @param header
	 * @return
	 */
	public JWTBuilder setJSONHeader(String header) {
		this.header = HMAC.encodeBase64(header.getBytes());
		return this;
	}

	/**
	 * Set the base64 encoded payload
	 * 
	 * @param encodedHeader
	 * @return
	 */
	public JWTBuilder setEncodedPayload(String payload) {
		this.payload = payload;
		return this;
	}

	/**
	 * Set a JSON payload. The payload will be base64 encoded.
	 * 
	 * @param encodedHeader
	 * @return
	 */
	public JWTBuilder setJSONPayload(String payload) {
		this.payload = HMAC.encodeBase64(payload.getBytes());
		return this;
	}

	/**
	 * Signs the header+payload
	 * 
	 * @return
	 * @throws InvalidKeyException
	 * @throws NoSuchAlgorithmException
	 */
	public JWTBuilder sign() throws JWTException {
		String message = header + "." + payload;
		byte[] bSignature;
		try {
			bSignature = HMAC.createSignature(key, message.getBytes());
		} catch (InvalidKeyException e) {
			throw new JWTException("INVALID_KEY", "Invalid key!", e);

		} catch (NoSuchAlgorithmException e) {
			throw new JWTException("INVALID_ALGORITHM", "Invalid algorithm!", e);
		}

		signature = HMAC.encodeBase64(bSignature);

		return this;

	}

	/**
	 * Returns the base64 encoded signature
	 * 
	 * @return
	 */
	public String getSignature() {
		return signature;
	}

	/**
	 * Returns the JSON Web Token. At a minimum the Key and payload must be set
	 * before. If no header was set, the header is created based on the Key. If
	 * no signature was generated, the signature will be added.
	 * 
	 * @return
	 * @throws JWTException
	 */
	public String getToken() throws JWTException {
		if (key == null) {
			throw new JWTException("MISSING_SECRET_KEY", "No SecretKey defined!");
		}

		if (payload == null || payload.isEmpty()) {
			throw new JWTException("MISSING_PAYLOAD", "No Payload defined!");
		}

		if (header == null) {
			// create default header
			setJSONHeader("{\"alg\":\"" + key.getAlgorithm() + "\",\"typ\":\"JWT\"}");
		}

		if (signature == null) {
			// create signature
			sign();
		}

		return header + "." + payload + "." + signature;

	}

}