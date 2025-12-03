package ir.bpmellat.springsecurity.config;

import ir.bpmellat.springsecurity.entity.User;
import ir.bpmellat.springsecurity.repository.UserRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@Component
public class DataInitializer implements CommandLineRunner {
    
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    
    public DataInitializer(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }
    
    @Override
    public void run(String... args) {
        // Create default users if they don't exist
        if (!userRepository.existsByUsername("user")) {
            User user = User.builder()
                    .username("user")
                    .password(passwordEncoder.encode("password"))
                    .email("user@example.com")
                    .roles("USER")
                    .build();
            userRepository.save(user);
        }
        
        if (!userRepository.existsByUsername("admin")) {
            User admin = User.builder()
                    .username("admin")
                    .password(passwordEncoder.encode("admin"))
                    .email("admin@example.com")
                    .roles("ADMIN,USER")
                    .build();
            userRepository.save(admin);
        }
    }
}

