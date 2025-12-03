package ir.bpmellat.springsecurity.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;

@Entity
@Table(name = "oauth2_authorization")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class OAuth2AuthorizationEntity {
    
    @Id
    @Column(length = 100)
    private String id;
    
    @Column(name = "registered_client_id", length = 100, nullable = false)
    private String registeredClientId;
    
    @Column(name = "principal_name", length = 200, nullable = false)
    private String principalName;
    
    @Column(name = "authorization_grant_type", length = 100, nullable = false)
    private String authorizationGrantType;
    
    @Column(name = "authorized_scopes", length = 1000)
    private String authorizedScopes;
    
    @Column(name = "attributes", length = 4000)
    private String attributes;
    
    @Column(name = "state", length = 500)
    private String state;
    
    @Column(name = "authorization_code_value", length = 4000)
    private String authorizationCodeValue;
    
    @Column(name = "authorization_code_issued_at")
    private Instant authorizationCodeIssuedAt;
    
    @Column(name = "authorization_code_expires_at")
    private Instant authorizationCodeExpiresAt;
    
    @Column(name = "authorization_code_metadata", length = 2000)
    private String authorizationCodeMetadata;
    
    @Column(name = "access_token_value", length = 4000)
    private String accessTokenValue;
    
    @Column(name = "access_token_issued_at")
    private Instant accessTokenIssuedAt;
    
    @Column(name = "access_token_expires_at")
    private Instant accessTokenExpiresAt;
    
    @Column(name = "access_token_metadata", length = 2000)
    private String accessTokenMetadata;
    
    @Column(name = "access_token_type", length = 100)
    private String accessTokenType;
    
    @Column(name = "access_token_scopes", length = 1000)
    private String accessTokenScopes;
    
    @Column(name = "refresh_token_value", length = 4000)
    private String refreshTokenValue;
    
    @Column(name = "refresh_token_issued_at")
    private Instant refreshTokenIssuedAt;
    
    @Column(name = "refresh_token_expires_at")
    private Instant refreshTokenExpiresAt;
    
    @Column(name = "refresh_token_metadata", length = 2000)
    private String refreshTokenMetadata;
}

