package org.kilois.experiments.jaspicexperiment.security;

import java.util.HashMap;
import java.util.Map;
import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.message.AuthException;
import javax.security.auth.message.AuthStatus;
import javax.security.auth.message.MessageInfo;
import javax.security.auth.message.MessagePolicy;
import javax.security.auth.message.config.ServerAuthContext;

public class JaspicExperimentServerAuthContext implements ServerAuthContext {

    private JaspicExperimentServerAuthModule serverAuthModule;

    public JaspicExperimentServerAuthContext(MessagePolicy requestPolicy, MessagePolicy responsePolicy,
            Map<String, String> extraModuleOptions, CallbackHandler handler) throws AuthException {
        super();

        this.serverAuthModule = new JaspicExperimentServerAuthModule();
        Map<String, String> moduleOptions = new HashMap<String, String>();
        if (extraModuleOptions != null) {
            moduleOptions.putAll(extraModuleOptions);
        }
        this.serverAuthModule.initialize(requestPolicy, responsePolicy, handler, moduleOptions);
    }

    @Override
    public AuthStatus validateRequest(MessageInfo messageInfo, Subject clientSubject, Subject serviceSubject)
            throws AuthException {
        return this.serverAuthModule.validateRequest(messageInfo, clientSubject, serviceSubject);
    }

    @Override
    public AuthStatus secureResponse(MessageInfo messageInfo, Subject serviceSubject) throws AuthException {
        return this.serverAuthModule.secureResponse(messageInfo, serviceSubject);
    }

    @Override
    public void cleanSubject(MessageInfo messageInfo, Subject subject) throws AuthException {
        this.serverAuthModule.cleanSubject(messageInfo, subject);
    }

}
