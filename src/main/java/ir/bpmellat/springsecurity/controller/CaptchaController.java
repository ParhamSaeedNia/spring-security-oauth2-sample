package ir.bpmellat.springsecurity.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import ir.bpmellat.springsecurity.service.CaptchaService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/captcha")
@Tag(name = "CAPTCHA", description = "CAPTCHA generation and validation endpoints")
public class CaptchaController {
    
    private final CaptchaService captchaService;
    
    public CaptchaController(CaptchaService captchaService) {
        this.captchaService = captchaService;
    }
    
    @GetMapping("/generate")
    @Operation(summary = "Generate a new CAPTCHA", 
               description = "Generates a new CAPTCHA ID. Use this ID when calling login or register endpoints. " +
                           "The CAPTCHA value is stored server-side and must be provided by the user.")
    @ApiResponse(responseCode = "200", description = "CAPTCHA ID generated successfully")
    public ResponseEntity<Map<String, String>> generateCaptcha() {
        String captchaId = captchaService.generateCaptcha();
        String captchaValue = captchaService.getCaptchaValue(captchaId);
        
        Map<String, String> response = new HashMap<>();
        response.put("captcha_id", captchaId);
        response.put("captcha_value", captchaValue); // In production, this should be returned as an image
        response.put("message", "CAPTCHA generated. Use captcha_id and captcha_value in login/register requests.");
        response.put("expires_in_minutes", "5");
        
        return ResponseEntity.ok(response);
    }
}

