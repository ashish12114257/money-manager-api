package in.ashishkumar.moneymanager.controller;

import in.ashishkumar.moneymanager.dto.AuthDTO;
import in.ashishkumar.moneymanager.dto.ProfileDTO;
import in.ashishkumar.moneymanager.service.ProfileService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequiredArgsConstructor
@Slf4j
public class ProfileController {
    private final ProfileService profileService;

    @PostMapping("/register")
    public ResponseEntity<?> registerProfile(@RequestBody ProfileDTO profileDTO) {
        log.info("=== REGISTER ENDPOINT CALLED ===");
        log.info("Request received for email: {}", profileDTO.getEmail());
        log.info("Full name: {}", profileDTO.getFullName());

        try {
            ProfileDTO registeredProfile = profileService.registerProfile(profileDTO);
            log.info("Registration successful for: {}", profileDTO.getEmail());
            return ResponseEntity.status(HttpStatus.CREATED).body(registeredProfile);
        } catch (Exception e) {
            log.error("Registration failed for {}: {}", profileDTO.getEmail(), e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(Map.of(
                            "error", "Registration failed",
                            "message", e.getMessage()
                    ));
        }
    }

    @PostMapping("/register-test")
    public ResponseEntity<Map<String, String>> registerTest(@RequestBody ProfileDTO profileDTO) {
        log.info("Register test endpoint called with email: {}", profileDTO.getEmail());

        // Simple validation
        if (profileDTO.getEmail() == null || profileDTO.getEmail().isEmpty()) {
            return ResponseEntity.badRequest().body(Map.of("error", "Email is required"));
        }

        return ResponseEntity.ok(Map.of(
                "message", "Test endpoint works!",
                "email", profileDTO.getEmail(),
                "fullName", profileDTO.getFullName() != null ? profileDTO.getFullName() : "N/A",
                "status", "Security configuration is correct"
        ));
    }

    @GetMapping("/activate")
    public ResponseEntity<String> activateProfile(@RequestParam String token) {
        log.info("Activation endpoint called with token: {}", token);
        boolean isActivated = profileService.activateProfile(token);
        if (isActivated) {
            return ResponseEntity.ok("Profile activated successfully");
        } else {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body("Activation token not found or already used");
        }
    }

    @PostMapping("/login")
    public ResponseEntity<Map<String, Object>> login(@RequestBody AuthDTO authDTO) {
        log.info("Login attempt for email: {}", authDTO.getEmail());
        try {
            if (!profileService.isAccountActive(authDTO.getEmail())) {
                return ResponseEntity.status(HttpStatus.FORBIDDEN).body(Map.of(
                        "message", "Account is not active. Please activate your account first."
                ));
            }
            Map<String, Object> response = profileService.authenticateAndGenerateToken(authDTO);
            log.info("Login successful for: {}", authDTO.getEmail());
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            log.error("Login failed for {}: {}", authDTO.getEmail(), e.getMessage());
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(Map.of(
                    "message", e.getMessage()
            ));
        }
    }
}