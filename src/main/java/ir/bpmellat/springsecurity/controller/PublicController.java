package ir.bpmellat.springsecurity.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/public")
@Tag(name = "Public API", description = "Public endpoints that don't require authentication")
public class PublicController {
    
    @GetMapping("/info")
    @Operation(summary = "Get public information", 
               description = "Returns public information about the OAuth2 server")
    @ApiResponse(responseCode = "200", description = "Public information retrieved")
    public ResponseEntity<Map<String, Object>> getPublicInfo() {
        Map<String, Object> info = new HashMap<>();
        info.put("message", "This is a public endpoint");
        info.put("authorization_endpoint", "http://localhost:8080/oauth2/authorize");
        info.put("token_endpoint", "http://localhost:8080/oauth2/token");
        info.put("jwks_endpoint", "http://localhost:8080/.well-known/jwks.json");
        info.put("client_id", "api-client");
        info.put("redirect_uri", "http://localhost:8080/login/oauth2/code/api-client");
        return ResponseEntity.ok(info);
    }
}

