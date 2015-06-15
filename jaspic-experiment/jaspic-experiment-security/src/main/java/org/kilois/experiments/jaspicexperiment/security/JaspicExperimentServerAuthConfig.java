package org.kilois.experiments.jaspicexperiment.security;

import java.util.Map;
import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.message.AuthException;
import javax.security.auth.message.MessageInfo;
import javax.security.auth.message.config.ServerAuthConfig;
import javax.security.auth.message.config.ServerAuthContext;
import lombok.Getter;

public class JaspicExperimentServerAuthConfig implements ServerAuthConfig {

    protected static final String DESCRIPTION = "JASPIC Experiment server auth* configuration";

    @Getter
    private String messageLayer;

    @Getter
    private String appContext;

    @Getter
    private boolean Protected = false; // JCC conventions overridden because "protected" is a reserved word

    private CallbackHandler handler;

    public JaspicExperimentServerAuthConfig(String messageLayer, String appContext, CallbackHandler handler) {
        super();

        this.messageLayer = messageLayer;
        this.appContext = appContext;
        this.handler = handler;
    }

    @Override
    public String getAuthContextID(MessageInfo messageInfo) {
        return this.appContext;
    }

    @Override
    @SuppressWarnings({ "rawtypes", "unchecked" })
    public ServerAuthContext getAuthContext(String authContextId, Subject serviceSubject, Map properties)
            throws AuthException {
        return new JaspicExperimentServerAuthContext(null, null, properties, this.handler);
    }

    @Override
    public void refresh() {
        // Nothing to do here
    }

}
