package org.kilois.experiments.jaspicexperiment.security;

import java.util.Map;
import java.util.logging.Logger;
import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.message.AuthException;
import javax.security.auth.message.MessageInfo;
import javax.security.auth.message.config.ServerAuthConfig;
import javax.security.auth.message.config.ServerAuthContext;
import lombok.Getter;

public class JaspicExperimentServerAuthConfig implements ServerAuthConfig {

    protected static final String DESCRIPTION = "ReumaT server auth* configuration";

    private static final Logger LOGGER = Logger.getLogger(JaspicExperimentServerAuthConfig.class.getName());

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
        LOGGER.info(DESCRIPTION + " provided auth* context id " + this.appContext + " for " + messageInfo + ".");
        return this.appContext;
    }

    @Override
    @SuppressWarnings({ "rawtypes", "unchecked" })
    public ServerAuthContext getAuthContext(String authContextId, Subject serviceSubject, Map properties)
            throws AuthException {
        JaspicExperimentServerAuthContext authContext = new JaspicExperimentServerAuthContext(null, null, properties,
                this.handler);
        LOGGER.info(DESCRIPTION + " provided auth* context: " + authContext + ".");
        return authContext;
    }

    @Override
    public void refresh() {
        // Nothing to do here
        LOGGER.info(DESCRIPTION + " refreshed.");
    }

}
