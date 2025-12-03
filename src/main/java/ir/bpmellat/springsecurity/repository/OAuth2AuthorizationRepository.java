package ir.bpmellat.springsecurity.repository;

import ir.bpmellat.springsecurity.entity.OAuth2AuthorizationEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface OAuth2AuthorizationRepository extends JpaRepository<OAuth2AuthorizationEntity, String> {
    
    Optional<OAuth2AuthorizationEntity> findByState(String state);
    
    Optional<OAuth2AuthorizationEntity> findByAuthorizationCodeValue(String authorizationCode);
    
    Optional<OAuth2AuthorizationEntity> findByAccessTokenValue(String accessToken);
    
    Optional<OAuth2AuthorizationEntity> findByRefreshTokenValue(String refreshToken);
    
    @Query("SELECT a FROM OAuth2AuthorizationEntity a WHERE a.principalName = :principalName")
    Optional<OAuth2AuthorizationEntity> findByPrincipalName(@Param("principalName") String principalName);
}

