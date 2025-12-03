package ir.bpmellat.springsecurity.service;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.token.DefaultOAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.stereotype.Service;

import java.util.Set;
import java.util.UUID;

@Service
public class TokenGenerationService {
    
    private final OAuth2AuthorizationService authorizationService;
    private final RegisteredClientRepository registeredClientRepository;
    private final OAuth2TokenGenerator<? extends org.springframework.security.oauth2.core.OAuth2Token> tokenGenerator;
    private final AuthorizationServerSettings authorizationServerSettings;
    
    public TokenGenerationService(
            OAuth2AuthorizationService authorizationService,
            RegisteredClientRepository registeredClientRepository,
            OAuth2TokenGenerator<? extends org.springframework.security.oauth2.core.OAuth2Token> tokenGenerator,
            AuthorizationServerSettings authorizationServerSettings) {
        this.authorizationService = authorizationService;
        this.registeredClientRepository = registeredClientRepository;
        this.tokenGenerator = tokenGenerator;
        this.authorizationServerSettings = authorizationServerSettings;
    }
    
    public OAuth2Authorization generateTokens(Authentication authentication, String clientId) {
        RegisteredClient registeredClient = registeredClientRepository.findByClientId(clientId);
        if (registeredClient == null) {
            throw new IllegalArgumentException("Client not found: " + clientId);
        }
        
        String authorizationId = UUID.randomUUID().toString();
        OAuth2Authorization.Builder authorizationBuilder = OAuth2Authorization.withRegisteredClient(registeredClient)
                .id(authorizationId)
                .principalName(authentication.getName())
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .attribute(OAuth2ParameterNames.STATE, UUID.randomUUID().toString());
        
        Set<String> authorizedScopes = Set.of("read", "write", "openid", "profile");
        
        // Generate access token
        org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContext serverContext = 
                new org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContext() {
                    @Override
                    public String getIssuer() {
                        return authorizationServerSettings.getIssuer();
                    }
                    
                    @Override
                    public org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings getAuthorizationServerSettings() {
                        return authorizationServerSettings;
                    }
                };
        
        OAuth2TokenContext accessTokenContext = DefaultOAuth2TokenContext.builder()
                .registeredClient(registeredClient)
                .principal(authentication)
                .authorizationServerContext(serverContext)
                .tokenType(OAuth2TokenType.ACCESS_TOKEN)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrant(authentication)
                .authorizedScopes(authorizedScopes)
                .build();
        
        org.springframework.security.oauth2.core.OAuth2Token generatedAccessToken = tokenGenerator.generate(accessTokenContext);
        if (generatedAccessToken == null) {
            throw new IllegalStateException("Failed to generate access token");
        }
        
        OAuth2AccessToken accessToken = new OAuth2AccessToken(
                OAuth2AccessToken.TokenType.BEARER,
                generatedAccessToken.getTokenValue(),
                generatedAccessToken.getIssuedAt(),
                generatedAccessToken.getExpiresAt(),
                authorizedScopes
        );
        
        authorizationBuilder.token(accessToken);
        
        // Generate refresh token
        OAuth2TokenContext refreshTokenContext = DefaultOAuth2TokenContext.builder()
                .registeredClient(registeredClient)
                .principal(authentication)
                .authorizationServerContext(serverContext)
                .tokenType(OAuth2TokenType.REFRESH_TOKEN)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .authorizationGrant(authentication)
                .build();
        
        org.springframework.security.oauth2.core.OAuth2Token generatedRefreshToken = tokenGenerator.generate(refreshTokenContext);
        if (generatedRefreshToken != null) {
            OAuth2RefreshToken refreshToken = new OAuth2RefreshToken(
                    generatedRefreshToken.getTokenValue(),
                    generatedRefreshToken.getIssuedAt(),
                    generatedRefreshToken.getExpiresAt()
            );
            authorizationBuilder.token(refreshToken);
        }
        
        OAuth2Authorization authorization = authorizationBuilder.build();
        authorizationService.save(authorization);
        
        return authorization;
    }
}

