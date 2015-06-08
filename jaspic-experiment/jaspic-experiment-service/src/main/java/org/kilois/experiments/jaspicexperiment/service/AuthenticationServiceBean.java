package org.kilois.experiments.jaspicexperiment.service;

import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Map.Entry;
import java.util.Set;

import javax.ejb.EJB;
import javax.ejb.Stateless;

/** Authentication service */
// TODO Implement token expiration and refresh
@Stateless
@EJB(name = "java:global/JaspicExperiment/AuthenticationService", beanInterface = AuthenticationService.class)
public class AuthenticationServiceBean implements AuthenticationService.Local, AuthenticationService.Remote {

    private static final Map<String, char[]> USER_PASSWORDS = new HashMap<String, char[]>();
    static {
        USER_PASSWORDS.put("user", "password".toCharArray());
        USER_PASSWORDS.put("admin", "password".toCharArray());
        USER_PASSWORDS.put("intruder", null);
    }

    private static final Map<String, Set<String>> USER_GROUPS = new HashMap<String, Set<String>>();
    static {
        USER_GROUPS.put("user", set("users"));
        USER_GROUPS.put("admin", set("users", "admins"));
    }

    private static final Map<String, String> TOKENS = new HashMap<String, String>();

    public AuthenticationServiceBean() {
        super();
    }

    /** Password authentication method */
    @Override
    public AuthenticationResult authenticate(String userName, char[] password) {
        if (!USER_PASSWORDS.containsKey(userName)) {
            return AuthenticationResult.ofWrongInfo(userName);
        }

        char[] storedPassword = USER_PASSWORDS.get(userName);
        if (storedPassword == null) {
            return AuthenticationResult.ofNotAuthorized(userName);
        }

        if (!Arrays.equals(password, storedPassword)) {
        	return AuthenticationResult.ofNotAuthorized(userName, USER_GROUPS.get(userName));
        }

        String token = null;
        if (TOKENS.containsValue(userName)) {
        	for (Entry<String, String> tokenEntry : TOKENS.entrySet()) {
        		if (Objects.equals(tokenEntry.getValue(), userName)) {
        			token = tokenEntry.getKey();
        			break;
        		}
        	}
        } else {
        	token = createToken(userName);
        	TOKENS.put(token, userName);
        }

        return AuthenticationResult.ofLogged(userName, USER_GROUPS.get(userName), token);
    }

    private String createToken(String userName) {
		return userName; // TODO
	}

	/** Token authentication method */
    @Override
    public AuthenticationResult authenticate(String token) {
    	if (!TOKENS.containsKey(token)) {
    		return AuthenticationResult.ofExpired();
    	}

    	String userName = TOKENS.get(token);
        return AuthenticationResult.ofLogged(userName, USER_GROUPS.get(userName), token);
    }

    @SafeVarargs
    private static <T> Set<T> set(T... elements) {
        Set<T> set = new HashSet<T>();
        for (T element : elements) {
            set.add(element);
        }
        return set;
    }

}
