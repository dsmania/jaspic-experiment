package org.kilois.experiments.jaspicexperiment.service;

import java.util.Collections;
import java.util.Set;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.Getter;
import lombok.NonNull;
import lombok.Setter;

@Data
@Setter(AccessLevel.NONE)
@AllArgsConstructor(access = AccessLevel.PRIVATE)
public class AuthenticationResult {

    public static final String ERROR_PROPERTY = "error";
    public static final String GROUPS_PROPERTY = "groups";
    public static final String STATE_PROPERTY = "state";
    public static final String USER_NAME_PROPERTY = "userName";

    @NonNull
    private State state;

    private String userName;

    private Set<String> groups;

    public Set<String> getGroups() {
        return (this.groups != null) ? Collections.unmodifiableSet(this.groups) : null;
    }

    private String token;

    private String error;

    public boolean isAuthorized() {
        return this.state.isAuthorized();
    }

    public static AuthenticationResult ofLogged(String userName, Set<String> groups, String token) {
        return new AuthenticationResult(State.LOGGED, userName, groups, token, null);
    }

    public static AuthenticationResult ofWrongInfo(String userName) {
        return new AuthenticationResult(State.WRONG_INFO, userName, null, null, State.WRONG_INFO.toString());
    }

    public static AuthenticationResult ofNotAuthorized(String userName, Set<String> groups) {
        return new AuthenticationResult(State.NOT_AUTHORIZED, userName, groups, null, State.NOT_AUTHORIZED.toString());
    }

    public static AuthenticationResult ofNotAuthorized(String userName) {
        return new AuthenticationResult(State.NOT_AUTHORIZED, userName, null, null, State.NOT_AUTHORIZED.toString());
    }

    public static AuthenticationResult ofExpired() {
        return new AuthenticationResult(State.EXPIRED, null, null, null, State.EXPIRED.toString());
    }

    public static AuthenticationResult ofError(String error, String userName) {
        return new AuthenticationResult(State.ERROR, userName, null, null, error);
    }

    public static AuthenticationResult ofError(String error) {
        return new AuthenticationResult(State.ERROR, null, null, null, error);
    }

    public static AuthenticationResult ofError() {
        return new AuthenticationResult(State.ERROR, null, null, null, State.ERROR.toString());
    }


    @Getter
    @AllArgsConstructor
    public enum State {

        LOGGED(true, "User successfully logged"),
        WRONG_INFO(false, "Wrong user or password"),
        NOT_AUTHORIZED(false, "User not authorized"),
        EXPIRED(false, "Session expired"),
        ERROR(false, "Authentication error");

        private boolean authorized;

        @Getter(AccessLevel.NONE)
        private String text;

        public String toString() {
            return this.text;
        }

    }

}
