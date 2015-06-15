package org.kilois.experiments.jaspicexperiment.security;

import java.util.HashMap;
import java.util.Map;
import javax.security.auth.message.config.AuthConfigFactory;
import javax.servlet.ServletContext;
import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;
import javax.servlet.annotation.WebListener;

@WebListener
public class JaspicExperimentAuthStartupListener implements ServletContextListener {

    protected static final String CONTEXT_REGISTRATION_ID_KEY
            = "org.kilois.experiments.jaspicexperiment.security.registrationId";

    private static final String GLASSFISH = "GlassFish";
    private static final String WEBSPHERE = "Websphere";

    public JaspicExperimentAuthStartupListener() {
        super();
    }

    @Override
    public void contextInitialized(ServletContextEvent event) {
        ServletContext context = event.getServletContext();
        Map<String, String> properties = null;
        String hostName = getHostName(context); // In Java EE 7 context.getHostName()
        if (hostName != null) {
            properties = new HashMap<String, String>();
            properties.put(JaspicExperimentAuthConfigProvider.HOST_NAME_KEY, hostName);
        }
        String contextPath = context.getContextPath();
        if (contextPath != null) {
            if (properties == null) {
                properties = new HashMap<String, String>();
            }
            properties.put(JaspicExperimentAuthConfigProvider.CONTEXT_PATH_KEY, contextPath);
        }

        JaspicExperimentAuthConfigProvider configProvider = new JaspicExperimentAuthConfigProvider(properties,
                AuthConfigFactory.getFactory());
        context.setAttribute(CONTEXT_REGISTRATION_ID_KEY, configProvider.getRegistrationId());
    }

    /* Not accurate. Might be configured with another name, these are default ones. */
    private static String getHostName(ServletContext context) {
        if (context == null) {
            return null;
        }

        String serverInfo = context.getServerInfo();
        if (serverInfo == null) {
            return null;
        } else if (serverInfo.contains(GLASSFISH)) {
            return "server";
        } else if (serverInfo.equals(WEBSPHERE)) {
            return "default_host";
        }

        return null;
    }

    @Override
    public void contextDestroyed(ServletContextEvent event) {
        String registrationId = (String) event.getServletContext().getAttribute(CONTEXT_REGISTRATION_ID_KEY);
        if ((registrationId != null) && (!registrationId.isEmpty())) {
            AuthConfigFactory.getFactory().removeRegistration(registrationId);
        }
    }

}
