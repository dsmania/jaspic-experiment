package org.kilois.experiments.jaspicexperiment.security;

import java.io.IOException;
import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.TimeZone;
import javax.security.auth.message.AuthStatus;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import lombok.Data;

public class JaspicExperimentHttpFilter implements Filter {

    public static final String AUTHENTICATION_FROM_FILTER_KEY = "org.kilois.experiments.jaspicexperiment.security.request.authenticationFromFilter";
    public static final String DID_AUTHENTICATION_KEY = "org.kilois.experiments.jaspicexperiment.security.request.didAuthentication";
    public static final String LAST_AUTH_STATUS_KEY = "org.kilois.experiments.jaspicexperiment.security.authStatus";
    private static final String ORIGINAL_REQUEST_DATA_KEY = "org.kilois.experiments.jaspicexperiment.security.originalRequest";

    public JaspicExperimentHttpFilter() {
        super();
    }

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        // Nothing to do here
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws ServletException,
            IOException {
        HttpServletRequest httpRequest = (HttpServletRequest) request;
        HttpServletResponse httpResponse = (HttpServletResponse) response;
        HttpSession session = httpRequest.getSession(false);

        authenticateFromFilter(httpRequest, httpResponse);

        AuthStatus lastStatus = (AuthStatus) httpRequest.getAttribute(LAST_AUTH_STATUS_KEY);
        if ((lastStatus == null) || (lastStatus == AuthStatus.SUCCESS)) {
            HttpServletRequest newRequest = httpRequest;

            RequestData requestData = (session != null) ? (RequestData) session.getAttribute(ORIGINAL_REQUEST_DATA_KEY)
                    : null;
            if (requestData != null) {
                boolean matchesRequest = requestData.matchesRequest(httpRequest);

                if ((!matchesRequest) && (AuthStatus.SUCCESS.equals(lastStatus))
                        && (Boolean.TRUE.equals(httpRequest.getAttribute(DID_AUTHENTICATION_KEY)))
                        && (httpRequest.getUserPrincipal() != null)) {
                    try {
                        httpResponse.sendRedirect(requestData.getFullRequestUrl());
                    } catch (IOException e) {
                        throw new IllegalStateException(e);
                    }
                    return;
                }

                if (matchesRequest) {
                    if (requestData.isRestoreRequest()) {
                        newRequest = new HttpServletRequestDelegator(httpRequest, requestData);
                    }
                    httpRequest.getSession().removeAttribute(ORIGINAL_REQUEST_DATA_KEY);
                }
            }
            chain.doFilter(newRequest, httpResponse);
        }
    }

    public static boolean authenticateFromFilter(HttpServletRequest request, HttpServletResponse response) {
        try {
            request.setAttribute(AUTHENTICATION_FROM_FILTER_KEY, true);
            return request.authenticate(response);
        } catch (ServletException e) {
            // Ignored
            return false;
        } catch (IOException e) {
            throw new IllegalArgumentException(e);
        } finally {
            request.removeAttribute(AUTHENTICATION_FROM_FILTER_KEY);
        }
    }

    @Override
    public void destroy() {
        // Nothing to do here
    }


    @Data
    private static class RequestData {

        private Cookie[] cookies;
        private Map<String, List<String>> headers;
        private List<Locale> locales;
        private Map<String, String[]> parameters;
        private String method;
        private String requestUrl;
        private String queryString;
        private boolean restoreRequest = true;

        public String getFullRequestUrl() {
            return createFullRequestUrl(this.requestUrl, this.queryString);
        }

        public boolean matchesRequest(HttpServletRequest request) {
            return createFullRequestUrl(this.requestUrl, this.queryString).equals(createFullRequestUrl(
                    request.getRequestURL().toString(), request.getQueryString()));
        }

        @Override
        public String toString() {
            return this.method + " " + getFullRequestUrl();
        }

        private static String createFullRequestUrl(String requestUrl, String queryString) {
            return requestUrl + (((queryString != null) && (!queryString.isEmpty())) ? "?" + queryString : "");
        }

    }


    private static class HttpServletRequestDelegator extends HttpServletRequestWrapper {

        private static final TimeZone GMT = TimeZone.getTimeZone("GMT");
        private static final String[] DATE_PATTERNS = {
            "EE, dd MMM yyyy HH:mm:ss zz",
            "EEEE, dd-MMM-yy HH:mm:ss zz",
            "EE MMM  d HH:mm:ss yyyy"
        };

        private final RequestData requestData;
        private List<DateFormat> dateFormats;

        public HttpServletRequestDelegator(HttpServletRequest request, RequestData requestData) {
            super(request);

            this.requestData = requestData;
        }

        @Override
        public Cookie[] getCookies() {
            return this.requestData.getCookies();
        }

        @Override
        public Enumeration<String> getHeaderNames() {
            return Collections.enumeration(this.requestData.getHeaders().keySet());
        }

        @Override
        public String getHeader(String name) {
            for (Map.Entry<String, List<String>> header : this.requestData.getHeaders().entrySet()) {
                if ((header.getKey().equalsIgnoreCase(name)) && (!(header.getValue().isEmpty()))) {
                    return header.getValue().get(0);
                }
            }

            return null;
        }

        @Override
        public Enumeration<String> getHeaders(String name) {
            List<String> headers = new ArrayList<>();
            for (Map.Entry<String, List<String>> header : this.requestData.getHeaders().entrySet()) {
                if (header.getKey().equalsIgnoreCase(name)) {
                    headers.addAll(header.getValue());
                }
            }

            return Collections.enumeration(headers);
        }

        @Override
        public int getIntHeader(String name) {
            String header = getHeader(name);
            if (header == null) {
                return -1;
            }

            return Integer.parseInt(header);
        }

        @Override
        public long getDateHeader(String name) {
            String header = getHeader(name);
            if (header == null) {
                return -1;
            }

            if (this.dateFormats == null) {
                this.dateFormats = new ArrayList<>(DATE_PATTERNS.length);
                for (String datePattern : DATE_PATTERNS) {
                    this.dateFormats.add(createDateFormat(datePattern));
                }
            }

            for (DateFormat dateFormat : this.dateFormats) {
                try {
                    return dateFormat.parse(header).getTime();
                } catch (ParseException e) {
                    // Nothing to do here
                }
            }

            throw new IllegalArgumentException("Can't convert " + header + " to a date");
        }

        @Override
        public Map<String, String[]> getParameterMap() {
            return this.requestData.getParameters();
        }

        @Override
        public String getParameter(String name) {
            String[] values = this.requestData.getParameters().get(name);
            if ((values == null) || (values.length == 0)) {
                return null;
            }

            return values[0];
        }

        @Override
        public Enumeration<String> getParameterNames() {
            return Collections.enumeration(getParameterMap().keySet());
        }

        @Override
        public String[] getParameterValues(String name) {
            return getParameterMap().get(name);
        }

        @Override
        public Enumeration<Locale> getLocales() {
            return Collections.enumeration(this.requestData.getLocales());
        }

        @Override
        public Locale getLocale() {
            if (this.requestData.getLocales().isEmpty()) {
                return Locale.getDefault();
            }

            return this.requestData.getLocales().get(0);
        }

        @Override
        public String getMethod() {
            return this.requestData.getMethod();
        }

        private DateFormat createDateFormat(String pattern) {
            DateFormat dateFormat = new SimpleDateFormat(pattern, Locale.US);
            dateFormat.setTimeZone(GMT);
            return dateFormat;
        }

    }

}
