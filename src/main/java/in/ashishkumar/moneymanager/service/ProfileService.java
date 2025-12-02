package in.ashishkumar.moneymanager.service;

import in.ashishkumar.moneymanager.dto.AuthDTO;
import in.ashishkumar.moneymanager.dto.ProfileDTO;
import in.ashishkumar.moneymanager.entity.ProfileEntity;
import in.ashishkumar.moneymanager.repository.ProfileRepository;
import in.ashishkumar.moneymanager.util.JwtUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Map;
import java.util.UUID;

@Service
@RequiredArgsConstructor
@Slf4j
public class ProfileService {

    private final ProfileRepository profileRepository;
    private final EmailService emailService;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final JwtUtil jwtUtil;

    @Value("${app.activation.url:https://money-manager-api-4-yvy5.onrender.com}")
    private String activationURL;

    @Transactional
    public ProfileDTO registerProfile(ProfileDTO profileDTO) {
        log.info("Starting registration process for: {}", profileDTO.getEmail());

        try {
            // Check if email already exists
            if (profileRepository.findByEmail(profileDTO.getEmail()).isPresent()) {
                log.warn("Email already exists: {}", profileDTO.getEmail());
                throw new RuntimeException("Email already registered");
            }

            // Validate input
            if (profileDTO.getEmail() == null || profileDTO.getEmail().trim().isEmpty()) {
                throw new RuntimeException("Email is required");
            }
            if (profileDTO.getPassword() == null || profileDTO.getPassword().trim().isEmpty()) {
                throw new RuntimeException("Password is required");
            }
            if (profileDTO.getFullName() == null || profileDTO.getFullName().trim().isEmpty()) {
                throw new RuntimeException("Full name is required");
            }

            // Create profile entity
            ProfileEntity newProfile = ProfileEntity.builder()
                    .fullName(profileDTO.getFullName())
                    .email(profileDTO.getEmail())
                    .password(passwordEncoder.encode(profileDTO.getPassword()))
                    .profileImageUrl(profileDTO.getProfileImageUrl())
                    .activationToken(UUID.randomUUID().toString())
                    .isActive(false)
                    .build();

            log.info("Saving profile to database...");
            newProfile = profileRepository.save(newProfile);
            log.info("Profile saved with ID: {}", newProfile.getId());

            // Send activation email
            try {
                String activationLink = activationURL + "/api/v1.0/activate?token=" + newProfile.getActivationToken();
                String subject = "Activate your Money Manager account";
                String body = "Click on the following link to activate your account: " + activationLink;
                emailService.sendEmail(newProfile.getEmail(), subject, body);
                log.info("Activation email sent to: {}", newProfile.getEmail());
            } catch (Exception emailError) {
                log.warn("Failed to send activation email: {}. Registration will continue.", emailError.getMessage());
                // Don't fail registration if email fails
            }

            return toDTO(newProfile);

        } catch (Exception e) {
            log.error("Registration failed for {}: {}", profileDTO.getEmail(), e.getMessage(), e);
            throw new RuntimeException("Registration failed: " + e.getMessage());
        }
    }

    public ProfileEntity toEntity(ProfileDTO profileDTO) {
        return ProfileEntity.builder()
                .id(profileDTO.getId())
                .fullName(profileDTO.getFullName())
                .email(profileDTO.getEmail())
                .password(passwordEncoder.encode(profileDTO.getPassword()))
                .profileImageUrl(profileDTO.getProfileImageUrl())
                .build();
    }

    public ProfileDTO toDTO(ProfileEntity profileEntity) {
        return ProfileDTO.builder()
                .id(profileEntity.getId())
                .fullName(profileEntity.getFullName())
                .email(profileEntity.getEmail())
                .profileImageUrl(profileEntity.getProfileImageUrl())
                .createdAt(profileEntity.getCreatedAt())
                .updatedAt(profileEntity.getUpdatedAt())
                .build();
    }

    public boolean activateProfile(String activationToken) {
        log.info("Attempting to activate profile with token: {}", activationToken);
        return profileRepository.findByActivationToken(activationToken)
                .map(profile -> {
                    profile.setIsActive(true);
                    profileRepository.save(profile);
                    log.info("Profile activated: {}", profile.getEmail());
                    return true;
                })
                .orElse(false);
    }

    public boolean isAccountActive(String email) {
        return profileRepository.findByEmail(email)
                .map(ProfileEntity::getIsActive)
                .orElse(false);
    }

    public ProfileEntity getCurrentProfile() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        return profileRepository.findByEmail(authentication.getName())
                .orElseThrow(() -> new UsernameNotFoundException("Profile not found with email: " + authentication.getName()));
    }

    public ProfileDTO getPublicProfile(String email) {
        ProfileEntity currentUser = null;
        if (email == null) {
            currentUser = getCurrentProfile();
        }else {
            currentUser = profileRepository.findByEmail(email)
                    .orElseThrow(() -> new UsernameNotFoundException("Profile not found with email: " + email));
        }

        return ProfileDTO.builder()
                .id(currentUser.getId())
                .fullName(currentUser.getFullName())
                .email(currentUser.getEmail())
                .profileImageUrl(currentUser.getProfileImageUrl())
                .createdAt(currentUser.getCreatedAt())
                .updatedAt(currentUser.getUpdatedAt())
                .build();
    }

    public Map<String, Object> authenticateAndGenerateToken(AuthDTO authDTO) {
        try {
            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(authDTO.getEmail(), authDTO.getPassword()));
            //Generate JWT token
            String token = jwtUtil.generateToken(authDTO.getEmail());
            return Map.of(
                    "token", token,
                    "user", getPublicProfile(authDTO.getEmail())
            );
        } catch (Exception e) {
            throw new RuntimeException("Invalid email or password");
        }
    }
}