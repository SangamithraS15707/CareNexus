
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

@Service
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    
    public AuthService(
            UserRepository userRepository,
            PasswordEncoder passwordEncoder,
            JwtService jwtService) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtService = jwtService;
    }

    @Transactional
    public User register(String fullName, String email, String rawPassword) {

        String normalizedEmail = email.trim().toLowerCase();

        if (userRepository.existsByEmailIgnoreCase(normalizedEmail)) {
            throw new IllegalArgumentException("Email is already registered");
        }

        User user = new User(fullName.trim(), normalizedEmail, passwordEncoder.encode(rawPassword), Role.PATIENT    );
        

        return userRepository.save(user);
    }

    public String login(String email, String rawPassword) {

    String normalizedEmail = email.trim().toLowerCase(Locale.ROOT);

    User user = userRepository.findByEmailIgnoreCase(normalizedEmail).orElseThrow(() ->new BadCredentialsException("Invalid email or password"));

    if (!passwordEncoder.matches(rawPassword, user.getPassword())) {
        throw new BadCredentialsException("Invalid email or password");
    }

    return jwtService.generateToken(user);
}

}
