package org.kilois.experiments.jaspicexperiment.service;

import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import javax.ejb.EJB;
import javax.ejb.Stateless;

/** Authentication service */
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

	public AuthenticationServiceBean() {
		super();
	}

    /** Authentication method */
	@Override
	public AuthenticationResult authenticate(String userName, char[] password) {
		if (!USER_PASSWORDS.containsKey(userName)) {
			return AuthenticationResult.ofWrongInfo(userName);
		}

		char[] storedPassword = USER_PASSWORDS.get(userName);
		if (storedPassword == null) {
			return AuthenticationResult.ofNotAuthorized(userName);
		}

		return (Arrays.equals(password, storedPassword))
				? AuthenticationResult.ofLogged(userName, USER_GROUPS.get(userName))
				: AuthenticationResult.ofNotAuthorized(userName, USER_GROUPS.get(userName));
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
