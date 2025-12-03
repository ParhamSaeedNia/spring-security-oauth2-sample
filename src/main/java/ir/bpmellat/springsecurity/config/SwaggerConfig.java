package ir.bpmellat.springsecurity.config;

import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Contact;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.info.License;
import io.swagger.v3.oas.models.security.SecurityScheme;
import io.swagger.v3.oas.models.servers.Server;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.List;

@Configuration
public class SwaggerConfig {
    
    @Bean
    public OpenAPI customOpenAPI() {
        return new OpenAPI()
                .info(new Info()
                        .title("OAuth2 Authorization Server API")
                        .version("1.0.0")
                        .description("""
                                A fully functional OAuth2 Authorization Server implementation using Spring Security.
                                
                                ## Features:
                                - Authorization Code Grant Flow
                                - Access Token and Refresh Token support
                                - HTTP-only cookies for token storage
                                - Custom token validation
                                - H2 Database for token persistence
                                - Resource Server with JWT validation
                                
                                ## Authentication Flow:
                                1. Get authorization code: `GET /oauth2/authorize?client_id=api-client&response_type=code&redirect_uri=http://localhost:8080/login/oauth2/code/api-client&scope=read write`
                                2. Exchange code for tokens: `POST /api/auth/token?code={code}&client_id=api-client&redirect_uri=http://localhost:8080/login/oauth2/code/api-client`
                                3. Use access token to access protected resources: `GET /api/resource/data`
                                4. Refresh token: `POST /api/auth/refresh`
                                
                                ## Default Credentials:
                                - Username: `user` / Password: `password`
                                - Username: `admin` / Password: `admin`
                                
                                ## Client Credentials:
                                - Client ID: `api-client`
                                - Client Secret: `secret`
                                """)
                        .contact(new Contact()
                                .name("Spring Security OAuth2")
                                .email("support@example.com"))
                        .license(new License()
                                .name("Apache 2.0")
                                .url("https://www.apache.org/licenses/LICENSE-2.0.html")))
                .servers(List.of(
                        new Server()
                                .url("http://localhost:8080")
                                .description("Local Development Server")
                ))
                .components(new Components()
                        .addSecuritySchemes("bearerAuth", new SecurityScheme()
                                .type(SecurityScheme.Type.HTTP)
                                .scheme("bearer")
                                .bearerFormat("JWT")
                                .description("JWT token obtained from the authorization server")));
    }
}

