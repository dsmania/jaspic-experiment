package org.kilois.experiments.jaspicexperiment.service;

public interface AuthenticationService {

    public AuthenticationResult authenticate(String userName, char[] password);


    @javax.ejb.Remote
    public static interface Remote extends AuthenticationService {

        /* No remote only methods */

    }


    @javax.ejb.Local
    public static interface Local extends AuthenticationService {

        /* No local only methods */

    }

}
