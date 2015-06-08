package org.kilois.experiments.jaspicexperiment.security;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Properties;

import javax.naming.InitialContext;
import javax.naming.NamingException;
import javax.security.auth.message.AuthException;

import lombok.Getter;

import org.kilois.experiments.jaspicexperiment.service.AuthenticationResult;
import org.kilois.experiments.jaspicexperiment.service.AuthenticationService;

// TODO Generate and store tokens
public class JaspicExperimentAuthenticator {

    private static final String SERVICE_NAME = "java:global/JaspicExperiment/AuthenticationService";

    private static InitialContext INITIAL_CONTEXT;

    @Getter
    private String userName;

    @Getter
    private boolean authenticated;

    private List<String> groups;

	public List<String> getGroups() {
		return Collections.unmodifiableList(this.groups);
	}

    @Getter
    private String token;

    public JaspicExperimentAuthenticator() {
    	super();
    }

	public boolean authenticate(String userName, String password) throws AuthException {
		AuthenticationService authenticationService;
		try {
			authenticationService = lookupAuthenticationService();
		} catch (NamingException e) {
			throw (AuthException) new AuthException().initCause(e);
		}
		AuthenticationResult result = authenticationService.authenticate(userName, password.toCharArray());
		if (!result.isAuthorized()) {
			return this.authenticated = false;
		}

		this.userName = userName;
		this.groups = new ArrayList<String>(result.getGroups());
		this.token = result.getToken();
		return this.authenticated = true;
	}

	public boolean authenticate(String token) throws AuthException {
        try {
			return this.authenticated = lookupAuthenticationService().authenticate(token).isAuthorized();
		} catch (NamingException e) {
			throw (AuthException) new AuthException().initCause(e);
		}
	}

    protected static AuthenticationService lookupAuthenticationService() throws NamingException {
        return lookupService(SERVICE_NAME, AuthenticationService.class);
    }

    protected static <T> T lookupService(String serviceName, Class<T> serviceType) throws NamingException {
        if (INITIAL_CONTEXT == null) {
            Properties properties = new Properties();
            properties.put(InitialContext.INITIAL_CONTEXT_FACTORY,
                    "com.sun.enterprise.naming.SerialInitContextFactory");
            properties.put(InitialContext.URL_PKG_PREFIXES, "com.sun.enterprise.naming");
            properties.put(InitialContext.STATE_FACTORIES,
                    "com.sun.corba.ee.impl.presentation.rmi.JNDIStateFactoryImpl");

            INITIAL_CONTEXT = new InitialContext(properties);
        }

        return serviceType.cast(INITIAL_CONTEXT.lookup(serviceName));
    }

}
