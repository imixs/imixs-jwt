package org.imixs.jwt.jaspic;

import java.io.StringReader;
import java.util.Arrays;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.crypto.SecretKey;
import javax.json.Json;
import javax.json.JsonArray;
import javax.json.JsonException;
import javax.json.JsonObject;
import javax.json.JsonReader;
import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.message.AuthException;
import javax.security.auth.message.AuthStatus;
import javax.security.auth.message.MessageInfo;
import javax.security.auth.message.MessagePolicy;
import javax.security.auth.message.callback.CallerPrincipalCallback;
import javax.security.auth.message.callback.GroupPrincipalCallback;
import javax.security.auth.message.config.ServerAuthContext;
import javax.security.auth.message.module.ServerAuthModule;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.imixs.jwt.HMAC;
import org.imixs.jwt.JWSAlgorithm;
import org.imixs.jwt.JWTException;
import org.imixs.jwt.JWTParser;

/**
 * This Class is a JASPIC AuthModule to authenticate users based on a JWT token.
 * 
 * If the token is set the user will be authenticated and the token will be
 * stored in the user session.
 * 
 * If the token is not set the user will not be authenticated.
 * 
 * @author rsoika,
 */
@SuppressWarnings("unchecked")
public class JWTAuthModule implements ServerAuthModule, ServerAuthContext {

	@SuppressWarnings("rawtypes")
	protected static final Class[] supportedMessageTypes = new Class[] { javax.servlet.http.HttpServletRequest.class,
			javax.servlet.http.HttpServletResponse.class };

	@SuppressWarnings("rawtypes")
	protected Map options;
	protected CallbackHandler handler;
	protected MessagePolicy requestPolicy;
	protected MessagePolicy responsePolicy;

	private static final String IS_MANDATORY_INFO_KEY = "javax.security.auth.message.MessagePolicy.isMandatory";
	private static final String AUTH_TYPE_INFO_KEY = "javax.servlet.http.authType";
	private static final String QUERY_PARAM_SESSION = "jwt";
	private static final String MODULE_OPTION_SECRET = "secret";

	protected static final String JWT_SUBJECT = "imixs.jwt.sub";
	protected static final String JWT_GROUPS = "imixs.jwt.groups";
	protected static final String JWT_PAYLOAD = "imixs.jwt.payload";

	protected final Logger logger = Logger.getLogger(JWTAuthModule.class.getName());

	/**
	 * get Module specific options as configured in options Map
	 * 
	 * 
	 */
	@SuppressWarnings("rawtypes")
	@Override
	public void initialize(MessagePolicy requestPolicy, MessagePolicy responsePolicy, CallbackHandler handler,
			Map options) throws AuthException {
		logger.fine("initialize....");
		this.requestPolicy = requestPolicy;
		this.responsePolicy = responsePolicy;
		this.handler = handler;
		this.options = options;
		if (options == null || !options.containsKey(MODULE_OPTION_SECRET)) {
			logger.warning("Missing module-option - option 'secret' was not found!");
		} else {
			logger.fine("options=" + options);
		}
	}

	/**
	 * Authenticate a received service request. This method conveys the outcome
	 * of its message processing either by returning an AuthStatus value or by
	 * throwing an AuthException.
	 * 
	 * @param messageInfo
	 *            A contextual object that encapsulates the client request and
	 *            server response objects, and that may be used to save state
	 *            across a sequence of calls made to the methods of this
	 *            interface for the purpose of completing a secure message
	 *            exchange.
	 * 
	 * @param clientSubject
	 *            A Subject that represents the source of the service request.
	 *            It is used by the method implementation to store Principals
	 *            and credentials validated in the request.
	 * 
	 * @param serviceSubject
	 *            A Subject that represents the recipient of the service
	 *            request, or null.
	 * 
	 * @return An AuthStatus object representing the completion status of the
	 *         processing performed by the method. The AuthStatus values that
	 *         may be returned by this method are defined as follows:
	 * 
	 *         <ul>
	 *         <li>AuthStatus.SUCCESS when the application request message was
	 *         successfully validated.
	 * 
	 *         <li>AuthStatus.SEND_FAILURE to indicate that message validation
	 *         failed and that an appropriate failure response message is
	 *         available by calling getResponseMessage on messageInfo.
	 *         </ul>
	 * 
	 * @exception AuthException
	 *                When the message processing failed without establishing a
	 *                failure response message (in messageInfo).
	 */
	@Override
	public AuthStatus validateRequest(MessageInfo messageInfo, Subject clientSubject, Subject serviceSubject)
			throws AuthException {

		// authentication mandatory...
		HttpServletRequest request = (HttpServletRequest) messageInfo.getRequestMessage();
		HttpServletResponse response = (HttpServletResponse) messageInfo.getResponseMessage();

		String payload = null;
		try {
			// First we consume the JWT in any way - even if the requested URL is not
			// mandatory
			payload = consumeJWTPayload(request, response);

			// verify if authentication for the requested resource is mandatory
			Object mandatoryKey = messageInfo.getMap().get(IS_MANDATORY_INFO_KEY);
			if (mandatoryKey == null || Boolean.parseBoolean(mandatoryKey.toString()) == false) {
				logger.finest("request not mandatory");
				// no further validation is needed.
				return AuthStatus.SUCCESS;
			}

			if (payload == null) {
				logger.fine("validateRequest failed!");
				cleanSubject(messageInfo, clientSubject);
				return AuthStatus.FAILURE;
			} else {
				// set the caller principal
				String id = "" + request.getSession().getAttribute(JWT_SUBJECT);
				String[] groups = (String[]) request.getSession().getAttribute(JWT_GROUPS);
				setCallerPrincipal(id, clientSubject, groups);
				messageInfo.getMap().put(AUTH_TYPE_INFO_KEY, "JWS");
				logger.fine("user logged in");
				return AuthStatus.SUCCESS;
			}
		} catch (JWTException e) {
			logger.severe(e.getMessage());
			cleanSubject(messageInfo, clientSubject);
			e.printStackTrace();
			return AuthStatus.FAILURE;
		}
	}

	/**
	 * Remove method specific principals and credentials from the subject.
	 * 
	 * @param messageInfo
	 *            a contextual object that encapsulates the client request and
	 *            server response objects, and that may be used to save state
	 *            across a sequence of calls made to the methods of this
	 *            interface for the purpose of completing a secure message
	 *            exchange.
	 * 
	 * @param subject
	 *            the Subject instance from which the Principals and credentials
	 *            are to be removed.
	 * 
	 * @exception AuthException
	 *                If an error occurs during the Subject processing.
	 */
	@Override
	public void cleanSubject(MessageInfo messageInfo, Subject subject) throws AuthException {
		if (subject != null) {
			logger.fine("clean_subject");
			HttpServletRequest request = (HttpServletRequest) messageInfo.getRequestMessage();
			request.getSession().removeAttribute(JWT_PAYLOAD);
			request.getSession().removeAttribute(JWT_SUBJECT);
			request.getSession().removeAttribute(JWT_GROUPS);
			subject.getPrincipals().clear();
			logger.fine("user logged out");
		}
	}

	/**
	 * Secure a service response before sending it to the client.
	 * 
	 * This method is called to transform the response message acquired by
	 * calling getResponseMessage (on messageInfo) into the mechanism-specific
	 * form to be sent by the runtime.
	 * <p>
	 * This method conveys the outcome of its message processing either by
	 * returning an AuthStatus value or by throwing an AuthException.
	 * 
	 * @param messageInfo
	 *            A contextual object that encapsulates the client request and
	 *            server response objects, and that may be used to save state
	 *            across a sequence of calls made to the methods of this
	 *            interface for the purpose of completing a secure message
	 *            exchange.
	 * 
	 * @param serviceSubject
	 *            A Subject that represents the source of the service response,
	 *            or null. It may be used by the method implementation to
	 *            retrieve Principals and credentials necessary to secure the
	 *            response. If the Subject is not null, the method
	 *            implementation may add additional Principals or credentials
	 *            (pertaining to the source of the service response) to the
	 *            Subject.
	 * 
	 * @return An AuthStatus object representing the completion status of the
	 *         processing performed by the method. The AuthStatus values that
	 *         may be returned by this method are defined as follows:
	 * 
	 *         <ul>
	 *         <li>AuthStatus.SEND_SUCCESS when the application response message
	 *         was successfully secured. The secured response message may be
	 *         obtained by calling getResponseMessage on messageInfo.
	 * 
	 *         <li>AuthStatus.SEND_CONTINUE to indicate that the application
	 *         response message (within messageInfo) was replaced with a
	 *         security message that should elicit a security-specific response
	 *         (in the form of a request) from the peer.
	 * 
	 *         This status value serves to inform the calling runtime that (to
	 *         successfully complete the message exchange) it will need to be
	 *         capable of continuing the message dialog by processing at least
	 *         one additional request/response exchange (after having sent the
	 *         response message returned in messageInfo).
	 * 
	 *         When this status value is returned, the application response must
	 *         be saved by the authentication module such that it can be
	 *         recovered when the module's validateRequest message is called to
	 *         process the elicited response.
	 * 
	 *         <li>AuthStatus.SEND_FAILURE to indicate that a failure occurred
	 *         while securing the response message and that an appropriate
	 *         failure response message is available by calling
	 *         getResponseMeessage on messageInfo.
	 *         </ul>
	 * 
	 * @exception AuthException
	 *                When the message processing failed without establishing a
	 *                failure response message (in messageInfo).
	 * 
	 * @author this method was initial implemented by monzillo
	 */
	@Override
	public AuthStatus secureResponse(MessageInfo messageInfo, Subject serviceSubject) throws AuthException {
		return AuthStatus.SEND_SUCCESS;
	}

	/**
	 * Get the one or more Class objects representing the message types
	 * supported by the module.
	 * 
	 * @return An array of Class objects, with at least one element defining a
	 *         message type supported by the module.
	 */
	@SuppressWarnings("rawtypes")
	@Override
	public Class[] getSupportedMessageTypes() {
		return supportedMessageTypes;
	}

	/*
	 * 
	 * 
	 * Helper Methods
	 */

	/**
	 * This Method extracts a JSON Web Token and returns the payload of the current token. If the
	 * current request contains a JWT the method extracts the payload from the
	 * JSON Web Token and store the payload into the current session. If the
	 * request contains no JWT the method test if the session contains a payload
	 * to be returned.
	 * 
	 * @param request
	 * @return the payload or null if no valid payload exists.
	 * @throws JWTException
	 */
	private String consumeJWTPayload(HttpServletRequest request, HttpServletResponse response) throws JWTException {
		String _payload = null;
		logger.fine("consume JWT Payload....");

		// check the query string for JWT....
		String token = null;
		String queryString = request.getQueryString();
		if (queryString != null) {
			int iPos = queryString.indexOf(QUERY_PARAM_SESSION + "=");
			if (iPos > -1) {
				logger.fine("parsing query param " + QUERY_PARAM_SESSION + "....");

				iPos = iPos + (QUERY_PARAM_SESSION + "=").length() + 0;
				token = queryString.substring(iPos);

				iPos = token.indexOf("&");
				if (iPos > -1) {
					token = token.substring(0, iPos - 1);
				}
				logger.fine("jwt=" + token);
				// parse token...
				String secret = (String) options.get(MODULE_OPTION_SECRET);
				SecretKey secretKey = HMAC.createKey(JWSAlgorithm.JDK_HS256, secret.getBytes());
				_payload = new JWTParser().setKey(secretKey).setToken(token).verify().getPayload();
				logger.fine("payload=" + _payload);

				// extract payload.....
				JsonObject payloadObject = null;
				JsonReader reader = null;
				try {
					reader = Json.createReader(new StringReader(_payload));
					payloadObject = reader.readObject();

					// store payload into session
					request.getSession().setAttribute(JWT_PAYLOAD, _payload);

					// store sub (userid) into session
					request.getSession().setAttribute(JWT_SUBJECT, payloadObject.getString("sub"));
					// get the groups as an JSON array and convert them into a
					// String array
					JsonArray jsonGroups = payloadObject.getJsonArray("groups");
					String[] stringGroups = new String[jsonGroups.size()];
					for (int i = 0; i < stringGroups.length; i++) {
						stringGroups[i] = jsonGroups.getString(i);
					}
					// store groups into session
					request.getSession().setAttribute(JWT_GROUPS, stringGroups);

				} catch (javax.json.stream.JsonParsingException j1) {
					logger.severe("invalid payload=" + _payload);
					logger.severe("JSON object or array cannot be created due to i/o error: " + j1.getMessage());
					return null;
				} catch (JsonException j1) {
					logger.severe("invalid payload=" + _payload);
					logger.severe("JSON object or array cannot be created due to incorrect representation: "
							+ j1.getMessage());
					return null;
				} catch (ClassCastException j1) {
					logger.severe("invalid payload=" + _payload);
					logger.severe("JSON object or array cannot be created due to incorrect representation: "
							+ j1.getMessage());
					return null;
				} finally {

					if (reader != null) {
						reader.close();
					}
				}

				// log message
				logger.fine("sub=" + request.getSession().getAttribute(JWT_SUBJECT));
				logger.fine("groups=" + Arrays.toString((String[]) request.getSession().getAttribute(JWT_GROUPS)));
				// finish
				return _payload;

			}
		}

		// Not query parameter with a JWT was available.
		// we verify if we already have a paylod in the current session
		_payload = (String) request.getSession().getAttribute(JWT_PAYLOAD);

		if (_payload != null) {
			logger.fine("get payload from current session");
		}
		// finish
		return _payload;

	}

	private boolean setCallerPrincipal(String caller, Subject clientSubject, String[] userGroups) {
		boolean rvalue = true;
		boolean assignGroups = true;

		// create CallerPrincipalCallback
		CallerPrincipalCallback cPCB = new CallerPrincipalCallback(clientSubject, caller);

		if (cPCB.getName() == null && cPCB.getPrincipal() == null) {
			assignGroups = false;
		}

		try {
			handler.handle(
					(assignGroups ? new Callback[] { cPCB, new GroupPrincipalCallback(cPCB.getSubject(), userGroups) }
							: new Callback[] { cPCB }));

			logger.fine("AuthModule: caller_principal:" + cPCB.getName() + " " + cPCB.getPrincipal());

			logger.fine("AuthModule: assigned_Groups:" + userGroups);

		} catch (Exception e) {
			// should not happen
			logger.log(Level.WARNING, "jmac.failed_to_set_caller", e);
			rvalue = false;
		}

		return rvalue;
	}

}