package ir.bpmellat.springsecurity.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/resource")
@Tag(name = "Resource Server", description = "Protected resource endpoints")
@SecurityRequirement(name = "bearerAuth")
public class ResourceController {
    
    @GetMapping("/data")
    @Operation(summary = "Get protected data", 
               description = "Retrieves protected data. Requires a valid access token.")
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "Data retrieved successfully"),
        @ApiResponse(responseCode = "401", description = "Unauthorized - Invalid or missing token")
    })
    public ResponseEntity<Map<String, Object>> getData(Authentication authentication) {
        Map<String, Object> data = new HashMap<>();
        data.put("message", "This is protected data from the resource server");
        data.put("timestamp", Instant.now().toString());
        data.put("user", authentication.getName());
        
        if (authentication.getPrincipal() instanceof Jwt jwt) {
            data.put("token_issued_at", jwt.getIssuedAt());
            data.put("token_expires_at", jwt.getExpiresAt());
            data.put("scopes", jwt.getClaim("scope"));
        }
        
        return ResponseEntity.ok(data);
    }
    
    @GetMapping("/user")
    @Operation(summary = "Get user information", 
               description = "Retrieves user information from the JWT token")
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "User information retrieved"),
        @ApiResponse(responseCode = "401", description = "Unauthorized")
    })
    public ResponseEntity<Map<String, Object>> getUser(Authentication authentication) {
        Map<String, Object> userInfo = new HashMap<>();
        userInfo.put("username", authentication.getName());
        userInfo.put("authorities", authentication.getAuthorities());
        
        if (authentication.getPrincipal() instanceof Jwt jwt) {
            userInfo.put("subject", jwt.getSubject());
            userInfo.put("claims", jwt.getClaims());
        }
        
        return ResponseEntity.ok(userInfo);
    }
    
    @PostMapping("/data")
    @Operation(summary = "Create data", 
               description = "Creates new data. Requires write scope.")
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "Data created successfully"),
        @ApiResponse(responseCode = "401", description = "Unauthorized"),
        @ApiResponse(responseCode = "403", description = "Forbidden - Insufficient permissions")
    })
    public ResponseEntity<Map<String, Object>> createData(
            @RequestBody Map<String, Object> requestData,
            Authentication authentication) {
        Map<String, Object> response = new HashMap<>();
        response.put("message", "Data created successfully");
        response.put("created_by", authentication.getName());
        response.put("data", requestData);
        response.put("timestamp", Instant.now().toString());
        
        return ResponseEntity.ok(response);
    }
}

