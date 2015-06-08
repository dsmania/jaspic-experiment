package org.kilois.experiments.jaspicexperiment.security;

import java.util.Map;
import java.util.Objects;
import java.util.logging.Logger;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.message.AuthException;
import javax.security.auth.message.config.AuthConfigFactory;
import javax.security.auth.message.config.AuthConfigProvider;
import javax.security.auth.message.config.ClientAuthConfig;
import javax.security.auth.message.config.ServerAuthConfig;
import lombok.Getter;

public class JaspicExperimentAuthConfigProvider implements AuthConfigProvider {

    protected static final String DESCRIPTION = "JASPIC Experiment auth* configuration provider";
    protected static final String CALLBACK_HANDLER_KEY = "authconfigprovider.client.callbackhandler";
    protected static final String CONTEXT_PATH_KEY = "org.kilois.experiments.jaspicexperiment.security.contextPath";
    protected static final String HOST_NAME_KEY = "org.kilois.experiments.jaspicexperiment.security.hostName";
    protected static final String LAYER = "HttpServlet";

    private static final Logger LOGGER = Logger.getLogger(JaspicExperimentAuthConfigProvider.class.getName());

    private Map<String, String> properties;

    private String appContext;

    @Getter
    private String registrationId;

    @SuppressWarnings({ "rawtypes", "unchecked" })
    public JaspicExperimentAuthConfigProvider(Map properties, AuthConfigFactory factory) {
        super();

        this.properties = properties;

        if (factory != null) {
            String hostName = this.properties.get(HOST_NAME_KEY);
            String contextPath = this.properties.get(CONTEXT_PATH_KEY);
            this.appContext = ((hostName != null) && (contextPath != null)) ? hostName + " " + contextPath : null;
            this.registrationId = factory.registerConfigProvider(this, LAYER, this.appContext, DESCRIPTION);
            LOGGER.warning(DESCRIPTION + " registered for context \"" + this.appContext + "\" in " + LAYER
            		+ " layer with ID \"" + this.registrationId + "\".");
        }
    }

    @Override
    public ClientAuthConfig getClientAuthConfig(String layer, String appContext, CallbackHandler handler)
            throws AuthException {
        validateParameters(layer, appContext);

        LOGGER.warning(DESCRIPTION + " provides no client auth* configuration.");
        return null;
    }

    @Override
    public ServerAuthConfig getServerAuthConfig(String layer, String appContext, CallbackHandler handler)
            throws AuthException {
        validateParameters(layer, appContext);

        JaspicExperimentServerAuthConfig serverAuthConfig = new JaspicExperimentServerAuthConfig(layer, appContext,
                (handler != null) ? handler : createDefaultCallbackHandler());
        LOGGER.warning(DESCRIPTION + " provided server auth* configuration: " + serverAuthConfig + ".");
        return serverAuthConfig;
    }

    protected CallbackHandler createDefaultCallbackHandler() throws AuthException {
        String callbackHandlerClassName = System.getProperty(CALLBACK_HANDLER_KEY);
        if (callbackHandlerClassName == null) {
            throw new AuthException("No default handler set via system property: " + CALLBACK_HANDLER_KEY);
        }

        try {
            return (CallbackHandler) Thread.currentThread().getContextClassLoader().loadClass(callbackHandlerClassName)
                    .newInstance();
        } catch (Exception e) {
            throw (AuthException) new AuthException().initCause(e);
        }
    }

    @Override
    public void refresh() {
        // Nothing to do here
        LOGGER.warning(DESCRIPTION + " refreshed.");
    }

    protected void validateParameters(String layer, String appContext) throws AuthException {
        if (layer == null) {
            throw new NullPointerException("Layer must not be null");
        }
        if (appContext == null) {
            throw new NullPointerException("Application context must not be null");
        }
        if (!LAYER.equals(layer)) {
            throw new AuthException("Invalid layer");
        }
        if ((this.appContext != null) && (!Objects.equals(this.appContext, appContext))) {
            throw new AuthException("Invalid application context: " + this.appContext + " != " + appContext);
        }
    }

}
