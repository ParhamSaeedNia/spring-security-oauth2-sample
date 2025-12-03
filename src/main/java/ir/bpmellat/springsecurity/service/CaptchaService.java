package ir.bpmellat.springsecurity.service;

import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

@Service
public class CaptchaService {
    
    private static final String CAPTCHA_CHARS = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    private static final int CAPTCHA_LENGTH = 6;
    private static final long CAPTCHA_EXPIRY_MINUTES = 5;
    
    private final Map<String, CaptchaData> captchaStore = new ConcurrentHashMap<>();
    private final SecureRandom random = new SecureRandom();
    private final ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(1);
    
    public CaptchaService() {
        // Clean up expired CAPTCHAs every minute
        scheduler.scheduleAtFixedRate(this::cleanupExpiredCaptchas, 1, 1, TimeUnit.MINUTES);
    }
    
    public String generateCaptcha() {
        StringBuilder captcha = new StringBuilder();
        for (int i = 0; i < CAPTCHA_LENGTH; i++) {
            captcha.append(CAPTCHA_CHARS.charAt(random.nextInt(CAPTCHA_CHARS.length())));
        }
        
        String captchaId = java.util.UUID.randomUUID().toString();
        String captchaValue = captcha.toString();
        
        captchaStore.put(captchaId, new CaptchaData(captchaValue, 
                java.time.Instant.now().plus(CAPTCHA_EXPIRY_MINUTES, java.time.temporal.ChronoUnit.MINUTES)));
        
        return captchaId;
    }
    
    public String getCaptchaValue(String captchaId) {
        CaptchaData data = captchaStore.get(captchaId);
        if (data == null || data.isExpired()) {
            return null;
        }
        return data.getValue();
    }
    
    public boolean validateCaptcha(String captchaId, String userInput) {
        if (captchaId == null || userInput == null) {
            return false;
        }
        
        CaptchaData data = captchaStore.remove(captchaId); // Remove after validation (one-time use)
        if (data == null || data.isExpired()) {
            return false;
        }
        
        return data.getValue().equalsIgnoreCase(userInput.trim());
    }
    
    private void cleanupExpiredCaptchas() {
        captchaStore.entrySet().removeIf(entry -> entry.getValue().isExpired());
    }
    
    private static class CaptchaData {
        private final String value;
        private final java.time.Instant expiresAt;
        
        public CaptchaData(String value, java.time.Instant expiresAt) {
            this.value = value;
            this.expiresAt = expiresAt;
        }
        
        public String getValue() {
            return value;
        }
        
        public boolean isExpired() {
            return java.time.Instant.now().isAfter(expiresAt);
        }
    }
}

