package ir.bpmellat.springsecurity.config;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.oauth2.server.resource.web.BearerTokenResolver;
import org.springframework.security.oauth2.server.resource.web.DefaultBearerTokenResolver;

public class CookieBearerTokenResolver implements BearerTokenResolver {
    
    private final DefaultBearerTokenResolver defaultResolver = new DefaultBearerTokenResolver();
    private static final String ACCESS_TOKEN_COOKIE_NAME = "access_token";
    
    @Override
    public String resolve(HttpServletRequest request) {
        // First try to get token from Authorization header
        String token = defaultResolver.resolve(request);
        
        // If not found in header, try to get from cookie
        if (token == null && request.getCookies() != null) {
            for (Cookie cookie : request.getCookies()) {
                if (ACCESS_TOKEN_COOKIE_NAME.equals(cookie.getName())) {
                    token = cookie.getValue();
                    break;
                }
            }
        }
        
        return token;
    }
}

