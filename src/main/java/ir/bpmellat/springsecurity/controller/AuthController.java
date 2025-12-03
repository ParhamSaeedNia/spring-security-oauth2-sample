package ir.bpmellat.springsecurity.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import ir.bpmellat.springsecurity.entity.User;
import ir.bpmellat.springsecurity.service.TokenGenerationService;
import ir.bpmellat.springsecurity.service.UserService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.web.bind.annotation.*;

import java.time.Duration;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/auth")
@Tag(name = "Authentication", description = "Simple authentication endpoints with OAuth2 token generation")
public class AuthController {
    
    private final TokenGenerationService tokenGenerationService;
    private final UserService userService;
    private final AuthenticationManager authenticationManager;
    private final OAuth2AuthorizationService authorizationService;
    
    @Value("${server.servlet.context-path:}")
    private String contextPath;
    
    @Value("${oauth2.client-id:api-client}")
    private String defaultClientId;
    
    public AuthController(
            TokenGenerationService tokenGenerationService,
            UserService userService,
            AuthenticationManager authenticationManager,
            OAuth2AuthorizationService authorizationService) {
        this.tokenGenerationService = tokenGenerationService;
        this.userService = userService;
        this.authenticationManager = authenticationManager;
        this.authorizationService = authorizationService;
    }
    
    @PostMapping("/register")
    @Operation(summary = "Register a new user", 
               description = "Creates a new user account. Returns user information without tokens. Use /login to get tokens.")
    @ApiResponses(value = {
        @ApiResponse(responseCode = "201", description = "User successfully registered"),
        @ApiResponse(responseCode = "400", description = "Invalid input or username/email already exists")
    })
    public ResponseEntity<Map<String, Object>> register(
            @Valid @RequestBody RegisterRequest request) {
        try {
            User user = userService.register(request.username, request.password, request.email);
            
            Map<String, Object> response = new HashMap<>();
            response.put("message", "User registered successfully");
            response.put("username", user.getUsername());
            response.put("email", user.getEmail());
            
            return ResponseEntity.status(HttpStatus.CREATED).body(response);
        } catch (IllegalArgumentException e) {
            Map<String, Object> error = new HashMap<>();
            error.put("error", e.getMessage());
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(error);
        }
    }
    
    @PostMapping("/login")
    @Operation(summary = "Login and get OAuth2 tokens", 
               description = "Authenticates user with username and password, then generates OAuth2 access and refresh tokens. " +
                           "Tokens are returned in the response body and set as HTTP-only cookies. " +
                           "This endpoint handles the OAuth2 flow internally - no need to manually get authorization codes.")
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "Login successful, tokens generated"),
        @ApiResponse(responseCode = "401", description = "Invalid credentials")
    })
    public ResponseEntity<Map<String, Object>> login(
            @Valid @RequestBody LoginRequest request,
            HttpServletResponse response) {
        try {
            // Authenticate user
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(request.username, request.password)
            );
            
            SecurityContextHolder.getContext().setAuthentication(authentication);
            
            // Generate OAuth2 tokens
            OAuth2Authorization authorization = tokenGenerationService.generateTokens(
                    authentication, 
                    defaultClientId
            );
            
            OAuth2AccessToken accessToken = authorization.getAccessToken().getToken();
            OAuth2RefreshToken refreshToken = authorization.getRefreshToken() != null 
                    ? authorization.getRefreshToken().getToken() 
                    : null;
            
            // Set tokens as HTTP-only cookies
            setTokenCookies(response, accessToken, refreshToken);
            
            // Build response
            Map<String, Object> responseBody = new HashMap<>();
            responseBody.put("message", "Login successful");
            responseBody.put("access_token", accessToken.getTokenValue());
            responseBody.put("token_type", accessToken.getTokenType().getValue());
            responseBody.put("expires_in", accessToken.getExpiresAt().getEpochSecond() - 
                    java.time.Instant.now().getEpochSecond());
            if (refreshToken != null) {
                responseBody.put("refresh_token", refreshToken.getTokenValue());
            }
            responseBody.put("username", authentication.getName());
            
            return ResponseEntity.ok(responseBody);
        } catch (org.springframework.security.core.AuthenticationException e) {
            Map<String, Object> error = new HashMap<>();
            error.put("error", "Invalid username or password");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(error);
        }
    }
    
    private void setTokenCookies(HttpServletResponse response, OAuth2AccessToken accessToken, OAuth2RefreshToken refreshToken) {
        // Set access token as HTTP-only cookie
        Cookie accessTokenCookie = new Cookie("access_token", accessToken.getTokenValue());
        accessTokenCookie.setHttpOnly(true);
        accessTokenCookie.setSecure(false); // Set to true in production with HTTPS
        accessTokenCookie.setPath(contextPath.isEmpty() ? "/" : contextPath);
        accessTokenCookie.setMaxAge((int) Duration.between(
                java.time.Instant.now(), 
                accessToken.getExpiresAt()
        ).getSeconds());
        response.addCookie(accessTokenCookie);
        
        // Set refresh token as HTTP-only cookie
        if (refreshToken != null) {
            Cookie refreshTokenCookie = new Cookie("refresh_token", refreshToken.getTokenValue());
            refreshTokenCookie.setHttpOnly(true);
            refreshTokenCookie.setSecure(false); // Set to true in production with HTTPS
            refreshTokenCookie.setPath(contextPath.isEmpty() ? "/" : contextPath);
            refreshTokenCookie.setMaxAge((int) Duration.between(
                    java.time.Instant.now(), 
                    refreshToken.getExpiresAt()
            ).getSeconds());
            response.addCookie(refreshTokenCookie);
        }
    }
    
    @PostMapping("/refresh")
    @Operation(summary = "Refresh access token", 
               description = "Uses a refresh token to obtain a new access token. Refresh token can be provided as cookie or in request body.")
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "Token successfully refreshed"),
        @ApiResponse(responseCode = "400", description = "Invalid refresh token"),
        @ApiResponse(responseCode = "401", description = "Unauthorized")
    })
    public ResponseEntity<Map<String, String>> refresh(
            @Parameter(description = "Refresh token (optional if provided as cookie)")
            @RequestParam(value = "refresh_token", required = false) String refreshTokenParam,
            HttpServletRequest request,
            HttpServletResponse response) {
        
        String refreshTokenValue = refreshTokenParam;
        if (refreshTokenValue == null) {
            Cookie[] cookies = request.getCookies();
            if (cookies != null) {
                for (Cookie cookie : cookies) {
                    if ("refresh_token".equals(cookie.getName())) {
                        refreshTokenValue = cookie.getValue();
                        break;
                    }
                }
            }
        }
        
        if (refreshTokenValue == null) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).build();
        }
        
        OAuth2Authorization authorization = authorizationService.findByToken(
                refreshTokenValue, 
                OAuth2TokenType.REFRESH_TOKEN
        );
        
        if (authorization == null) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).build();
        }
        
        OAuth2AccessToken accessToken = authorization.getAccessToken().getToken();
        
        // Update access token cookie
        Cookie accessTokenCookie = new Cookie("access_token", accessToken.getTokenValue());
        accessTokenCookie.setHttpOnly(true);
        accessTokenCookie.setSecure(false);
        accessTokenCookie.setPath(contextPath.isEmpty() ? "/" : contextPath);
        accessTokenCookie.setMaxAge((int) Duration.between(
                java.time.Instant.now(), 
                accessToken.getExpiresAt()
        ).getSeconds());
        response.addCookie(accessTokenCookie);
        
        Map<String, String> responseBody = new HashMap<>();
        responseBody.put("access_token", accessToken.getTokenValue());
        responseBody.put("token_type", accessToken.getTokenType().getValue());
        responseBody.put("expires_in", String.valueOf(accessToken.getExpiresAt().getEpochSecond() - 
                java.time.Instant.now().getEpochSecond()));
        
        return ResponseEntity.ok(responseBody);
    }
    
    @PostMapping("/logout")
    @Operation(summary = "Logout", description = "Invalidates tokens and clears cookies")
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "Successfully logged out")
    })
    public ResponseEntity<Map<String, String>> logout(
            HttpServletRequest request,
            HttpServletResponse response) {
        
        // Clear cookies
        Cookie accessTokenCookie = new Cookie("access_token", "");
        accessTokenCookie.setHttpOnly(true);
        accessTokenCookie.setPath(contextPath.isEmpty() ? "/" : contextPath);
        accessTokenCookie.setMaxAge(0);
        response.addCookie(accessTokenCookie);
        
        Cookie refreshTokenCookie = new Cookie("refresh_token", "");
        refreshTokenCookie.setHttpOnly(true);
        refreshTokenCookie.setPath(contextPath.isEmpty() ? "/" : contextPath);
        refreshTokenCookie.setMaxAge(0);
        response.addCookie(refreshTokenCookie);
        
        Map<String, String> responseBody = new HashMap<>();
        responseBody.put("message", "Logged out successfully");
        
        return ResponseEntity.ok(responseBody);
    }
    
    @GetMapping("/me")
    @Operation(summary = "Get current user", description = "Returns information about the currently authenticated user")
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "User information retrieved"),
        @ApiResponse(responseCode = "401", description = "Unauthorized")
    })
    public ResponseEntity<Map<String, Object>> getCurrentUser(Authentication authentication) {
        Map<String, Object> userInfo = new HashMap<>();
        userInfo.put("name", authentication.getName());
        userInfo.put("authorities", authentication.getAuthorities());
        return ResponseEntity.ok(userInfo);
    }
    
    // Request DTOs
    @Schema(description = "Login request")
    public static class LoginRequest {
        @NotBlank(message = "Username is required")
        @Schema(description = "Username", example = "user", required = true)
        public String username;
        
        @NotBlank(message = "Password is required")
        @Schema(description = "Password", example = "password", required = true)
        public String password;
    }
    
    @Schema(description = "Register request")
    public static class RegisterRequest {
        @NotBlank(message = "Username is required")
        @Schema(description = "Username", example = "newuser", required = true)
        public String username;
        
        @NotBlank(message = "Password is required")
        @Schema(description = "Password", example = "password123", required = true)
        public String password;
        
        @NotBlank(message = "Email is required")
        @Email(message = "Email should be valid")
        @Schema(description = "Email address", example = "user@example.com", required = true)
        public String email;
    }
}

