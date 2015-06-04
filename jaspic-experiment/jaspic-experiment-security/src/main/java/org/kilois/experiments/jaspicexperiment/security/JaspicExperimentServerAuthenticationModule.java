package org.kilois.experiments.jaspicexperiment.security;

import java.io.IOException;
import java.util.Arrays;
import java.util.Map;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.message.AuthException;
import javax.security.auth.message.AuthStatus;
import javax.security.auth.message.MessageInfo;
import javax.security.auth.message.MessagePolicy;
import javax.security.auth.message.callback.CallerPrincipalCallback;
import javax.security.auth.message.callback.GroupPrincipalCallback;
import javax.security.auth.message.callback.PasswordValidationCallback;
import javax.security.auth.message.module.ServerAuthModule;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.codec.binary.Base64;

public class JaspicExperimentServerAuthenticationModule implements ServerAuthModule {

    @Deprecated
    protected static final String AUTHENTICATION_HEADER = "WWW-Authenticate";
    protected static final String AUTH_TYPE_INFO_KEY = "javax.servlet.http.authType";
    @Deprecated
    protected static final String AUTHORIZATION_HEADER = "authorization";
    @Deprecated
    protected static final String BASIC = "Basic";
    @Deprecated
    protected static final String GROUP_PROPERTY_NAME = "group.name";
	protected static final Class<?>[] SUPPORTED_MESSAGE_TYPES = new Class<?>[] {
		HttpServletRequest.class,
		HttpServletResponse.class };
    @Deprecated
    private static final String REALM_PROPERTY_NAME = "realm.name";
    private static final String NAME = "JaspicExperimentSAM";

    private MessagePolicy requestPolicy;

    private MessagePolicy responsePolicy;

    private CallbackHandler handler;

    private Map<String, String> options;

    @Deprecated
    private String realmName = null;
    @Deprecated
    private String defaultGroup[] = null;

    public JaspicExperimentServerAuthenticationModule() {
		super();
	}

    @Override
    @SuppressWarnings({ "rawtypes", "unchecked" })
    public void initialize(MessagePolicy requestPolicy, MessagePolicy responsePolicy, CallbackHandler handler,
            Map options) throws AuthException {
        this.requestPolicy = requestPolicy;
        this.responsePolicy = responsePolicy;
        this.handler = handler;
        this.options = options;
    }

	@Override
	@SuppressWarnings("rawtypes")
	public Class[] getSupportedMessageTypes() {
		return Arrays.copyOf(SUPPORTED_MESSAGE_TYPES, SUPPORTED_MESSAGE_TYPES.length);
	}

	@Override
	@Deprecated
	public AuthStatus validateRequest(MessageInfo messageInfo, Subject clientSubject, Subject serviceSubject)
			throws AuthException {
        try {

            String username = processAuthorizationToken(messageInfo, clientSubject);
            if ((username == null) && (requestPolicy.isMandatory())) {
                return sendAuthenticateChallenge(messageInfo);
            }

           setAuthenticationResult(username, clientSubject, messageInfo);
           return AuthStatus.SUCCESS;
        } catch (Exception e) {
            throw (AuthException) new AuthException().initCause(e);
        }
	}

	@Deprecated
	private String processAuthorizationToken(MessageInfo messageInfo, Subject clientSubject) throws AuthException {
        HttpServletRequest request = (HttpServletRequest) messageInfo.getRequestMessage();

        String token = request.getHeader(AUTHORIZATION_HEADER);

        if ((token == null) || (!(token.startsWith(BASIC + " ")))) {
            return null;
        }

        String decodedToken = new String(Base64.decodeBase64(token.substring(BASIC.length() + 1).trim()));

        int colonIndex = decodedToken.indexOf(':');
        if ((colonIndex <= 0) || (colonIndex >= decodedToken.length() - 1)) {
            return null;
        }

        String username = decodedToken.substring(0, colonIndex);

        PasswordValidationCallback pvc = new PasswordValidationCallback(clientSubject, username,
        		decodedToken.substring(colonIndex + 1).toCharArray());
        try {
        	this.handler.handle(new Callback[]{ pvc });
        	pvc.clearPassword();
		} catch (IOException | UnsupportedCallbackException e) {
            throw (AuthException) new AuthException().initCause(e);
        }

    	return pvc.getResult() ? username : null;
	}

	private AuthStatus sendAuthenticateChallenge(MessageInfo messageInfo) {
		String realm = (this.realmName != null) ? this.realmName
				: ((HttpServletRequest) messageInfo.getRequestMessage()).getServerName();

		HttpServletResponse response = (HttpServletResponse) messageInfo.getResponseMessage();
		response.setHeader(AUTHENTICATION_HEADER, BASIC + " realm=\"" + realm + "\"");
		response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);

		return AuthStatus.SEND_CONTINUE;
	}

	@SuppressWarnings("unchecked")
	private void setAuthenticationResult(String username, Subject clientSubject, MessageInfo messageInfo)
			throws IOException, UnsupportedCallbackException {
		handler.handle(new Callback[]{ new CallerPrincipalCallback(clientSubject, username) });

		if (username != null) {
			if (defaultGroup != null) {
				handler.handle(new Callback[]{ new GroupPrincipalCallback(clientSubject, defaultGroup) });
			}
			messageInfo.getMap().put(AUTH_TYPE_INFO_KEY, NAME);
		}
	}

    @Override
	public AuthStatus secureResponse(MessageInfo messageInfo, Subject serviceSubject) throws AuthException {
        return AuthStatus.SEND_SUCCESS;
	}

	@Override
	public void cleanSubject(MessageInfo messageInfo, Subject subject) throws AuthException {
		if (subject != null) {
			subject.getPrincipals().clear();
		}
	}

}
