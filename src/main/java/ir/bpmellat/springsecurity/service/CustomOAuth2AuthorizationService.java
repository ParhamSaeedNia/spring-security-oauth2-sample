package ir.bpmellat.springsecurity.service;

import ir.bpmellat.springsecurity.entity.OAuth2AuthorizationEntity;
import ir.bpmellat.springsecurity.repository.OAuth2AuthorizationRepository;
import org.springframework.dao.DataRetrievalFailureException;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;

@Service
public class CustomOAuth2AuthorizationService implements OAuth2AuthorizationService {
    
    private final OAuth2AuthorizationRepository authorizationRepository;
    private final RegisteredClientRepository registeredClientRepository;
    
    public CustomOAuth2AuthorizationService(
            OAuth2AuthorizationRepository authorizationRepository,
            RegisteredClientRepository registeredClientRepository) {
        this.authorizationRepository = authorizationRepository;
        this.registeredClientRepository = registeredClientRepository;
    }
    
    @Override
    @Transactional
    public void save(OAuth2Authorization authorization) {
        OAuth2AuthorizationEntity entity = toEntity(authorization);
        authorizationRepository.save(entity);
    }
    
    @Override
    @Transactional
    public void remove(OAuth2Authorization authorization) {
        authorizationRepository.deleteById(authorization.getId());
    }
    
    @Override
    public OAuth2Authorization findById(String id) {
        return authorizationRepository.findById(id)
                .map(this::toObject)
                .orElse(null);
    }
    
    @Override
    public OAuth2Authorization findByToken(String token, OAuth2TokenType tokenType) {
        if (tokenType == null) {
            return authorizationRepository.findByState(token)
                    .map(this::toObject)
                    .orElse(null);
        } else if (OAuth2ParameterNames.STATE.equals(tokenType.getValue())) {
            return authorizationRepository.findByState(token)
                    .map(this::toObject)
                    .orElse(null);
        } else if (OAuth2ParameterNames.CODE.equals(tokenType.getValue())) {
            return authorizationRepository.findByAuthorizationCodeValue(token)
                    .map(this::toObject)
                    .orElse(null);
        } else if (OAuth2TokenType.ACCESS_TOKEN.equals(tokenType)) {
            return authorizationRepository.findByAccessTokenValue(token)
                    .map(this::toObject)
                    .orElse(null);
        } else if (OAuth2TokenType.REFRESH_TOKEN.equals(tokenType)) {
            return authorizationRepository.findByRefreshTokenValue(token)
                    .map(this::toObject)
                    .orElse(null);
        }
        return null;
    }
    
    private OAuth2AuthorizationEntity toEntity(OAuth2Authorization authorization) {
        OAuth2AuthorizationEntity entity = new OAuth2AuthorizationEntity();
        entity.setId(authorization.getId());
        entity.setRegisteredClientId(authorization.getRegisteredClientId());
        entity.setPrincipalName(authorization.getPrincipalName());
        entity.setAuthorizationGrantType(authorization.getAuthorizationGrantType().getValue());
        entity.setAuthorizedScopes(String.join(",", authorization.getAuthorizedScopes()));
        entity.setAttributes(convertAttributes(authorization.getAttributes()));
        entity.setState(authorization.getAttribute(OAuth2ParameterNames.STATE));
        
        OAuth2Authorization.Token<OAuth2AuthorizationCode> authorizationCode = authorization.getToken(OAuth2AuthorizationCode.class);
        if (authorizationCode != null) {
            entity.setAuthorizationCodeValue(authorizationCode.getToken().getTokenValue());
            entity.setAuthorizationCodeIssuedAt(authorizationCode.getToken().getIssuedAt());
            entity.setAuthorizationCodeExpiresAt(authorizationCode.getToken().getExpiresAt());
            entity.setAuthorizationCodeMetadata(convertMetadata(authorizationCode.getMetadata()));
        }
        
        OAuth2Authorization.Token<OAuth2AccessToken> accessToken = authorization.getToken(OAuth2AccessToken.class);
        if (accessToken != null) {
            entity.setAccessTokenValue(accessToken.getToken().getTokenValue());
            entity.setAccessTokenIssuedAt(accessToken.getToken().getIssuedAt());
            entity.setAccessTokenExpiresAt(accessToken.getToken().getExpiresAt());
            entity.setAccessTokenMetadata(convertMetadata(accessToken.getMetadata()));
            entity.setAccessTokenType(accessToken.getToken().getTokenType().getValue());
            entity.setAccessTokenScopes(String.join(",", accessToken.getToken().getScopes()));
        }
        
        OAuth2Authorization.Token<OAuth2RefreshToken> refreshToken = authorization.getToken(OAuth2RefreshToken.class);
        if (refreshToken != null) {
            entity.setRefreshTokenValue(refreshToken.getToken().getTokenValue());
            entity.setRefreshTokenIssuedAt(refreshToken.getToken().getIssuedAt());
            entity.setRefreshTokenExpiresAt(refreshToken.getToken().getExpiresAt());
            entity.setRefreshTokenMetadata(convertMetadata(refreshToken.getMetadata()));
        }
        
        return entity;
    }
    
    private OAuth2Authorization toObject(OAuth2AuthorizationEntity entity) {
        RegisteredClient registeredClient = registeredClientRepository.findById(entity.getRegisteredClientId());
        if (registeredClient == null) {
            throw new DataRetrievalFailureException("The RegisteredClient with id '" + entity.getRegisteredClientId() + "' was not found in the RegisteredClientRepository.");
        }
        
        OAuth2Authorization.Builder builder = OAuth2Authorization.withRegisteredClient(registeredClient)
                .id(entity.getId())
                .principalName(entity.getPrincipalName())
                .authorizationGrantType(resolveAuthorizationGrantType(entity.getAuthorizationGrantType()))
                .authorizedScopes(parseScopes(entity.getAuthorizedScopes()));
        
        if (entity.getAttributes() != null) {
            builder.attributes(attrs -> attrs.putAll(parseAttributes(entity.getAttributes())));
        }
        
        if (entity.getState() != null) {
            builder.attribute(OAuth2ParameterNames.STATE, entity.getState());
        }
        
        if (entity.getAuthorizationCodeValue() != null) {
            OAuth2AuthorizationCode authorizationCode = new OAuth2AuthorizationCode(
                    entity.getAuthorizationCodeValue(),
                    entity.getAuthorizationCodeIssuedAt(),
                    entity.getAuthorizationCodeExpiresAt());
            builder.token(authorizationCode, metadata -> metadata.putAll(parseMetadata(entity.getAuthorizationCodeMetadata())));
        }
        
        if (entity.getAccessTokenValue() != null) {
            OAuth2AccessToken accessToken = new OAuth2AccessToken(
                    OAuth2AccessToken.TokenType.BEARER,
                    entity.getAccessTokenValue(),
                    entity.getAccessTokenIssuedAt(),
                    entity.getAccessTokenExpiresAt(),
                    parseScopes(entity.getAccessTokenScopes()));
            builder.token(accessToken, metadata -> metadata.putAll(parseMetadata(entity.getAccessTokenMetadata())));
        }
        
        if (entity.getRefreshTokenValue() != null) {
            OAuth2RefreshToken refreshToken = new OAuth2RefreshToken(
                    entity.getRefreshTokenValue(),
                    entity.getRefreshTokenIssuedAt(),
                    entity.getRefreshTokenExpiresAt());
            builder.token(refreshToken, metadata -> metadata.putAll(parseMetadata(entity.getRefreshTokenMetadata())));
        }
        
        return builder.build();
    }
    
    private String convertAttributes(java.util.Map<String, Object> attributes) {
        // Simple JSON-like string conversion (in production, use proper JSON library)
        return attributes.toString();
    }
    
    private java.util.Map<String, Object> parseAttributes(String attributes) {
        // Simple parsing (in production, use proper JSON library)
        java.util.Map<String, Object> map = new java.util.HashMap<>();
        if (attributes != null && !attributes.isEmpty()) {
            // Basic parsing - in production use Jackson or similar
            map.put("parsed", attributes);
        }
        return map;
    }
    
    private String convertMetadata(java.util.Map<String, Object> metadata) {
        return metadata.toString();
    }
    
    private java.util.Map<String, Object> parseMetadata(String metadata) {
        java.util.Map<String, Object> map = new java.util.HashMap<>();
        if (metadata != null && !metadata.isEmpty()) {
            map.put("parsed", metadata);
        }
        return map;
    }
    
    private Set<String> parseScopes(String scopes) {
        if (scopes == null || scopes.isEmpty()) {
            return new HashSet<>();
        }
        return java.util.Arrays.stream(scopes.split(","))
                .map(String::trim)
                .collect(Collectors.toSet());
    }
    
    private org.springframework.security.oauth2.core.AuthorizationGrantType resolveAuthorizationGrantType(String authorizationGrantType) {
        if (org.springframework.security.oauth2.core.AuthorizationGrantType.AUTHORIZATION_CODE.getValue().equals(authorizationGrantType)) {
            return org.springframework.security.oauth2.core.AuthorizationGrantType.AUTHORIZATION_CODE;
        } else if (org.springframework.security.oauth2.core.AuthorizationGrantType.REFRESH_TOKEN.getValue().equals(authorizationGrantType)) {
            return org.springframework.security.oauth2.core.AuthorizationGrantType.REFRESH_TOKEN;
        }
        return new org.springframework.security.oauth2.core.AuthorizationGrantType(authorizationGrantType);
    }
}

