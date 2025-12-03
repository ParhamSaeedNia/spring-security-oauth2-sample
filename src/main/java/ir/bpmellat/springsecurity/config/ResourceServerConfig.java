package ir.bpmellat.springsecurity.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.resource.web.BearerTokenResolver;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class ResourceServerConfig {
    
    @Bean
    public BearerTokenResolver bearerTokenResolver() {
        return new CookieBearerTokenResolver();
    }
    
    @Bean
    @Order(2)
    public SecurityFilterChain resourceServerSecurityFilterChain(
            HttpSecurity http,
            JwtDecoder jwtDecoder,
            BearerTokenResolver bearerTokenResolver) throws Exception {
        http
                .securityMatcher("/api/resource/**")
                .authorizeHttpRequests(authorize -> authorize
                        .anyRequest().authenticated()
                )
                .oauth2ResourceServer(oauth2 -> oauth2
                        .jwt(jwt -> jwt.decoder(jwtDecoder))
                        .bearerTokenResolver(bearerTokenResolver)
                );
        
        return http.build();
    }
}

