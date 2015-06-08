package org.kilois.experiments.jaspicexperiment.security;

import java.io.IOException;
import java.security.Principal;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.logging.Logger;

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

public class JaspicExperimentServerAuthModule implements ServerAuthModule {

    protected static final String AUTH_TYPE_KEY = "javax.servlet.http.authType";
    protected static final String FORM_ACTION = "/j_security_check";
    protected static final String FORM_PASSWORD = "j_password";
    protected static final String FORM_USERNAME = "j_username";
    protected static final String FORM_TOKEN = "j_token";
    protected static final String IS_MANDATORY_KEY = "javax.security.auth.message.MessagePolicy.isMandatory";
    protected static final String REGISTER_SESSION_KEY = "javax.servlet.http.registerSession";
    protected static final String REGISTER_SESSION_GLASSFISH_KEY = "com.sun.web.RealmAdapter.register";
    protected static final String SAVED_URL_KEY = "org.kilois.experiments.jaspicexperiment.security.savedurl";
    protected static final String SAVED_AUTHENTICATOR_KEY
            = "org.kilois.experiments.jaspicexperiment.security.authenticator";
    protected static final Class<?>[] SUPPORTED_MESSAGE_TYPES = new Class<?>[] {
        HttpServletRequest.class,
        HttpServletResponse.class };

    private static final String NAME = "JaspicExperimentSAM";

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
        LOGGER.info("ServerAuthModule.initialize(MessagePolicy, MessagePolicy, CallbackHandler, Map)");
        this.requestPolicy = requestPolicy;
        this.responsePolicy = responsePolicy;
        this.handler = handler;
        this.options = options;
    }

    @Override
    @SuppressWarnings("rawtypes")
    public Class[] getSupportedMessageTypes() {
        LOGGER.info("ServerAuthModule.getSupportedMessageTypes()");
        return Arrays.copyOf(SUPPORTED_MESSAGE_TYPES, SUPPORTED_MESSAGE_TYPES.length);
    }

    @SuppressWarnings({ "rawtypes", "unchecked" })
	@Override
    public AuthStatus validateRequest(MessageInfo messageInfo, Subject clientSubject, Subject serviceSubject)
            throws AuthException {
        LOGGER.info("ServerAuthModule.validateRequest(MessageInfo, Subject, Subject)");

        HttpServletRequest request = (HttpServletRequest) messageInfo.getRequestMessage();
        HttpServletResponse response = (HttpServletResponse) messageInfo.getResponseMessage();
    	HttpSession session = request.getSession();

        Principal userPrincipal = request.getUserPrincipal();
        LOGGER.info("userPrincipal = " + userPrincipal);
        if (userPrincipal != null) {
            try {
                this.handler.handle(new Callback[] { new CallerPrincipalCallback(clientSubject, userPrincipal) });
                return AuthStatus.SUCCESS;
            } catch (IOException | UnsupportedCallbackException e) {
                throw (AuthException) new AuthException().initCause(e);
            }
        }

        String userName = request.getParameter(FORM_USERNAME);
        LOGGER.info("userName = " + userName);
        String password = request.getParameter(FORM_PASSWORD);
        LOGGER.info("password = " + password);
        String servletPath = request.getServletPath();
        LOGGER.info("servletPath = " + servletPath);
        if ((servletPath.startsWith(FORM_ACTION)) && (userName != null) && (password != null)) {
            JaspicExperimentAuthenticator authenticator = new JaspicExperimentAuthenticator();
            if (authenticator.authenticate(userName, password)) {
            	session.setAttribute(SAVED_AUTHENTICATOR_KEY, authenticator);
                try {
                    response.sendRedirect(getBaseUrl(request) + "/token"); // FIXME
                } catch (IOException e) {
                    throw (AuthException) new AuthException().initCause(e);
                }
                return AuthStatus.SEND_CONTINUE;
            } else {
                try {
                    response.sendRedirect(getBaseUrl(request) + "/error.jsf"); // TODO
                } catch (IOException e) {
                    throw (AuthException) new AuthException().initCause(e);
                }
            }
        } else if ((servletPath.startsWith(FORM_ACTION)) && (request.getParameter(FORM_TOKEN) != null)) {
            JaspicExperimentAuthenticator authenticator = (JaspicExperimentAuthenticator) session.getAttribute(
            		SAVED_AUTHENTICATOR_KEY);
            if (authenticator == null) {
                try {
                    response.sendError(HttpServletResponse.SC_REQUEST_TIMEOUT);
                } catch (IOException e) {
                    // Ignored
                }
                return AuthStatus.SEND_FAILURE;
            }

            if (authenticator.authenticate((String) request.getParameter(FORM_TOKEN))) {
                String savedUrl = (String) session.getAttribute(SAVED_URL_KEY);
                if (savedUrl == null) {
                    savedUrl = getBaseUrl(request);
                    session.setAttribute(SAVED_URL_KEY, savedUrl);
                }

                try {
                    response.sendRedirect(savedUrl);
                } catch (IOException e) {
                    throw (AuthException) new AuthException().initCause(e);
                }
                return AuthStatus.SEND_CONTINUE;
            } else {
                try {
                    response.sendRedirect(getBaseUrl(request) + "/error.jsf"); // TODO
                } catch (IOException e) {
                    throw (AuthException) new AuthException().initCause(e);
                }
            }
        } else {
            JaspicExperimentAuthenticator authenticator = (JaspicExperimentAuthenticator) session.getAttribute(
            		SAVED_AUTHENTICATOR_KEY);
            String savedUrl = (String) session.getAttribute(SAVED_URL_KEY);
            if ((savedUrl != null) && (authenticator != null) && (authenticator.isAuthenticated())
            		&& (savedUrl.equals(getFullRequestUrl(request)))) {
                try {
                    this.handler.handle(new Callback[] { new CallerPrincipalCallback(clientSubject,
                            authenticator.getUserName()) });

                    List<String> groups = authenticator.getGroups();
                    if ((groups != null) && (!groups.isEmpty())) {
                        this.handler.handle(new Callback[] { new GroupPrincipalCallback(clientSubject,
                        		groups.toArray(new String[groups.size()])) });
                    }
                } catch (IOException | UnsupportedCallbackException e) {
                    throw (AuthException) new AuthException().initCause(e);
                }
                Map messageInfoMap = messageInfo.getMap();
                messageInfoMap.put(REGISTER_SESSION_KEY, Boolean.TRUE.toString());
                messageInfoMap.put(REGISTER_SESSION_GLASSFISH_KEY, Boolean.TRUE.toString());
                session.removeAttribute(SAVED_URL_KEY);
                session.removeAttribute(SAVED_AUTHENTICATOR_KEY);

                return AuthStatus.SUCCESS;
            }
        }

        if (Boolean.valueOf((String) messageInfo.getMap().get(IS_MANDATORY_KEY))) {
        	session.setAttribute(SAVED_URL_KEY, getFullRequestUrl(request));
            try {
                response.sendRedirect(getBaseUrl(request) + "/login.jsf"); // TODO
            } catch (IOException e) {
                throw (AuthException) new AuthException().initCause(e);
            }
            return AuthStatus.SEND_CONTINUE;
        }

        return AuthStatus.SUCCESS;
    }

    @Override
    public AuthStatus secureResponse(MessageInfo messageInfo, Subject serviceSubject) throws AuthException {
        LOGGER.info("ServerAuthModule.secureResponse(MessageInfo, Subject)");
        return AuthStatus.SEND_SUCCESS;
    }

    @Override
    public void cleanSubject(MessageInfo messageInfo, Subject subject) throws AuthException {
        LOGGER.info("ServerAuthModule.cleanSubject(MessageInfo, Subject)");
        if (subject != null) {
            subject.getPrincipals().clear();
        }
    }

    public static String getBaseUrl(HttpServletRequest request) {
        String url = request.getRequestURL().toString();
        return url.substring(0, url.length() - request.getRequestURI().length()) + request.getContextPath();
    }

    public static String getFullRequestUrl(HttpServletRequest request) {
        StringBuffer queryURL = request.getRequestURL();
        String queryString = request.getQueryString();
        
        return ((queryString == null || queryString.isEmpty()) ? queryURL : queryURL.append("?" + queryString)).toString();
    }

}
