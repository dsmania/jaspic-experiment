package org.kilois.experiments.jaspicexperiment.security;

import java.io.IOException;
import java.security.Principal;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.logging.Logger;
import javax.naming.InitialContext;
import javax.naming.NamingException;
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
import javax.security.auth.message.module.ServerAuthModule;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import org.kilois.experiments.jaspicexperiment.service.AuthenticationResult;
import org.kilois.experiments.jaspicexperiment.service.AuthenticationService;

public class JaspicExperimentServerAuthModule implements ServerAuthModule {

    protected static final String AUTH_TYPE_KEY = "javax.servlet.http.authType";
    protected static final String AUTH_RESULT_KEY = "org.kilois.experiments.jaspicexperiment.security.authResult";
    protected static final String FORM_CHECK_ACTION = "/j_security_check";
    protected static final String FORM_LOGOUT_ACTION = "/logout";
    protected static final String FORM_PASSWORD_FIELD = "j_password";
    protected static final String FORM_USERNAME_FIELD = "j_username";
    protected static final String IS_MANDATORY_KEY = "javax.security.auth.message.MessagePolicy.isMandatory";
    protected static final String REGISTER_SESSION_KEY = "javax.servlet.http.registerSession";
    protected static final String REGISTER_SESSION_GLASSFISH_KEY = "com.sun.web.RealmAdapter.register";
    protected static final String SAVED_URL_KEY = "org.kilois.experiments.jaspicexperiment.security.savedUrl";
    protected static final Class<?>[] SUPPORTED_MESSAGE_TYPES = new Class<?>[] {
        HttpServletRequest.class,
        HttpServletResponse.class };

    private static final String AUTHENTICATION_SERVICE_NAME
    		= "java:global/jaspic-experiment/jaspic-experiment-service/AuthenticationService";
    private static AuthenticationService AUTHENTICATION_SERVICE;

    /* Static cache is not the best option (it won't be shared across nodes) Better requesting again to the service. */
    private static final Map<String, String[]> GROUPS_CACHE = new HashMap<String, String[]>();

    private static final Logger LOGGER = Logger.getLogger(JaspicExperimentServerAuthModule.class.getName());

    private MessagePolicy requestPolicy;

    private MessagePolicy responsePolicy;

    private CallbackHandler handler;

    private Map<String, String> options;

    public JaspicExperimentServerAuthModule() {
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
	@SuppressWarnings({ "rawtypes", "unchecked" })
	public AuthStatus validateRequest(MessageInfo messageInfo, Subject clientSubject, Subject serviceSubject)
			throws AuthException {
		HttpServletRequest request = (HttpServletRequest) messageInfo.getRequestMessage();
		HttpServletResponse response = (HttpServletResponse) messageInfo.getResponseMessage();
		HttpSession session = request.getSession();

		Principal userPrincipal = request.getUserPrincipal();
		if (userPrincipal != null) {
			try {
				if (GROUPS_CACHE.containsKey(userPrincipal.getName())) {
					this.handler.handle(new Callback[] {
							new CallerPrincipalCallback(clientSubject, userPrincipal),
							new GroupPrincipalCallback(clientSubject, GROUPS_CACHE.get(userPrincipal.getName())) });
				} else {
					this.handler.handle(new Callback[] { new CallerPrincipalCallback(clientSubject, userPrincipal) });
				}
				return AuthStatus.SUCCESS;
			} catch (IOException | UnsupportedCallbackException e) {
				throw (AuthException) new AuthException().initCause(e);
			}
		}

		String userName = request.getParameter(FORM_USERNAME_FIELD);
		String password = request.getParameter(FORM_PASSWORD_FIELD);
		String servletPath = request.getServletPath();
		if ((servletPath.startsWith(FORM_CHECK_ACTION)) && (userName != null) && (password != null)) {
			AuthenticationResult result;
			try {
				result = getAuthenticationService().authenticate(userName, password.toCharArray());
			} catch (NamingException e) {
				throw (AuthException) new AuthException().initCause(e);
			}
			session.setAttribute(AUTH_RESULT_KEY, result);
			if (result.isAuthorized()) {
				try {
					response.sendRedirect((String) session.getAttribute(SAVED_URL_KEY));
				} catch (IOException e) {
					throw (AuthException) new AuthException().initCause(e);
				}
				return AuthStatus.SEND_CONTINUE;
			} else {
				try {
					response.sendRedirect(getBaseUrl(request) + "/error.jsf"); // FIXME Use web.xml value
				} catch (IOException e) {
					throw (AuthException) new AuthException().initCause(e);
				}
				return AuthStatus.SEND_FAILURE;
			}
		} else {
			AuthenticationResult result = (AuthenticationResult) session.getAttribute(AUTH_RESULT_KEY);
			String savedUrl = (String) session.getAttribute(SAVED_URL_KEY);
			if ((result != null) && (result.isAuthorized()) && (savedUrl != null)
					&& (savedUrl.equals(getFullRequestUrl(request)))) {
				try {
					Set<String> groupSet = result.getGroups();
					String[] groups = (groupSet != null) ? groupSet.toArray(new String[groupSet.size()]) : null;
					if ((groups != null) && (groups.length > 0)) {
						userName = result.getUserName();
						this.handler.handle(new Callback[] {
								new CallerPrincipalCallback(clientSubject, userName),
								new GroupPrincipalCallback(clientSubject, groups) });
						GROUPS_CACHE.put(userName, groups);
					} else {
						this.handler.handle(new Callback[] {
								new CallerPrincipalCallback(clientSubject, result.getUserName()) });
					}
				} catch (IOException | UnsupportedCallbackException e) {
					throw (AuthException) new AuthException().initCause(e);
				}
				Map messageInfoMap = messageInfo.getMap();
				messageInfoMap.put(REGISTER_SESSION_KEY, Boolean.TRUE.toString());
				messageInfoMap.put(REGISTER_SESSION_GLASSFISH_KEY, Boolean.TRUE.toString());
				session.removeAttribute(SAVED_URL_KEY);
				session.removeAttribute(AUTH_RESULT_KEY);

				return AuthStatus.SUCCESS;
			}
		}

		if (Boolean.valueOf((String) messageInfo.getMap().get(IS_MANDATORY_KEY))) {
			session.setAttribute(SAVED_URL_KEY, getFullRequestUrl(request));
			try {
				response.sendRedirect(getBaseUrl(request) + "/login.jsf"); // FIXME Use web.xml value
			} catch (IOException e) {
				throw (AuthException) new AuthException().initCause(e);
			}
			return AuthStatus.SEND_CONTINUE;
		}

		return AuthStatus.SUCCESS;
	}

    @Override
    public AuthStatus secureResponse(MessageInfo messageInfo, Subject serviceSubject) throws AuthException {
		HttpServletRequest request = (HttpServletRequest) messageInfo.getRequestMessage();
		HttpServletResponse response = (HttpServletResponse) messageInfo.getResponseMessage();
		HttpSession session = request.getSession();

		if (request.getServletPath().startsWith(FORM_LOGOUT_ACTION)) {
			try {
				response.sendRedirect(getBaseUrl(request));
			} catch (IOException e) {
				throw (AuthException) new AuthException().initCause(e);
			}
			session.invalidate();
			return AuthStatus.SEND_CONTINUE;
		}
 
		return AuthStatus.SEND_SUCCESS;
    }

    @Override
    public void cleanSubject(MessageInfo messageInfo, Subject subject) throws AuthException {
		((HttpServletRequest) messageInfo.getRequestMessage()).getSession().invalidate();;
        if (subject != null) {
            subject.getPrincipals().clear();
        }
    }

    protected static AuthenticationService getAuthenticationService() throws NamingException {
    	if (AUTHENTICATION_SERVICE == null) {
    		Properties properties = new Properties();
    		properties.put(InitialContext.INITIAL_CONTEXT_FACTORY, "com.sun.enterprise.naming.SerialInitContextFactory");
    		properties.put(InitialContext.URL_PKG_PREFIXES, "com.sun.enterprise.naming");
    		properties.put(InitialContext.STATE_FACTORIES, "com.sun.corba.ee.impl.presentation.rmi.JNDIStateFactoryImpl");

    		AUTHENTICATION_SERVICE = (AuthenticationService) (new InitialContext(properties)).lookup(AUTHENTICATION_SERVICE_NAME);
    	}

    	return AUTHENTICATION_SERVICE;
    }

    public static String getBaseUrl(HttpServletRequest request) {
        String url = request.getRequestURL().toString();
        return url.substring(0, url.length() - request.getRequestURI().length()) + request.getContextPath();
    }

    public static String getFullRequestUrl(HttpServletRequest request) {
        StringBuffer queryUrl = request.getRequestURL();
        String queryString = request.getQueryString();
        
        return (((queryString != null) && (!queryString.isEmpty())) ? queryUrl.append("?").append(queryString)
        		: queryUrl).toString();
    }

}
