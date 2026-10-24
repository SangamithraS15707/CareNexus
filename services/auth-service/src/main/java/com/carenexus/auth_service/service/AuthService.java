
package com.carenexus.auth_service.service;

import com.carenexus.auth_service.entity.Role;
import com.carenexus.auth_service.entity.User;
import com.carenexus.auth_service.repository.UserRepository;
import com.carenexus.auth_service.security.JwtService;
import org.springframework.security.authentication.BadCredentialsException;
import java.util.Locale;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import com.carenexus.auth_service.entity.EmailVerificationToken;
import com.carenexus.auth_service.repository.EmailVerificationTokenRepository;
import com.carenexus.auth_service.email.ResendEmailService;

import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.Base64;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;
@Service
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;   
private final EmailVerificationTokenRepository tokenRepository;
private final ResendEmailService resendEmailService;

private static final SecureRandom SECURE_RANDOM = new SecureRandom();
public AuthService(
        UserRepository userRepository,
        PasswordEncoder passwordEncoder,
        JwtService jwtService,
        EmailVerificationTokenRepository tokenRepository,
        ResendEmailService resendEmailService) {

    this.userRepository = userRepository;
    this.passwordEncoder = passwordEncoder;
    this.jwtService = jwtService;
    this.tokenRepository = tokenRepository;
    this.resendEmailService = resendEmailService;
}
    @Transactional
public User register(String fullName, String email, String rawPassword) {

    String normalizedEmail = email.trim().toLowerCase(Locale.ROOT);

    if (userRepository.existsByEmailIgnoreCase(normalizedEmail)) {
        throw new IllegalArgumentException("Email is already registered");
    }

    User user = new User(
            fullName.trim(),
            normalizedEmail,
            passwordEncoder.encode(rawPassword),
            Role.PATIENT
    );

    user = userRepository.save(user);

    byte[] randomBytes = new byte[32];
    SECURE_RANDOM.nextBytes(randomBytes);

    String token = Base64.getUrlEncoder()
            .withoutPadding()
            .encodeToString(randomBytes);

    EmailVerificationToken verificationToken =
            new EmailVerificationToken(
                    token,
                    user,
                    LocalDateTime.now().plusHours(24)
            );

    tokenRepository.save(verificationToken);

    String verificationUrl =
            "http://localhost:8080/api/auth/verify-email?token=" + token;

    try {
        resendEmailService.sendVerificationEmail(
                user.getEmail(), verificationUrl);
    } catch (Exception ex) {
        throw new IllegalStateException(
                "Could not send verification email. Please try again later.",
                ex
        );
    }

    return user;
}

    public String login(String email, String rawPassword) {

    String normalizedEmail = email.trim().toLowerCase(Locale.ROOT);

    User user = userRepository.findByEmailIgnoreCase(normalizedEmail).orElseThrow(() ->new BadCredentialsException("Invalid email or password"));

    if (!passwordEncoder.matches(rawPassword, user.getPassword())) {
        throw new BadCredentialsException("Invalid email or password");
    }
   if (!user.isEmailVerified()) {
    throw new ResponseStatusException(
            HttpStatus.FORBIDDEN,
            "Please verify your email before logging in"
    );
}
    return jwtService.generateToken(user);
}


@Transactional
public void verifyEmail(String token) {

    EmailVerificationToken verificationToken =
            tokenRepository.findByToken(token)
                    .orElseThrow(() -> new ResponseStatusException(
                            HttpStatus.BAD_REQUEST,
                            "Invalid verification link"
                    ));

    if (verificationToken.isExpired()) {
        throw new ResponseStatusException(
                HttpStatus.BAD_REQUEST,
                "Verification link has expired"
        );
    }

    User user = verificationToken.getUser();
    user.setEmailVerified(true);

    userRepository.save(user);

    // A verified token must never be reusable.
    tokenRepository.delete(verificationToken);
}

}