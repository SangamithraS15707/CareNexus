
package com.carenexus.auth_service.controller;

import com.carenexus.auth_service.dto.LoginRequest;
import com.carenexus.auth_service.dto.LoginResponse;
import com.carenexus.auth_service.dto.RegisterRequest;
import com.carenexus.auth_service.dto.RegisterResponse;
import com.carenexus.auth_service.entity.User;
import com.carenexus.auth_service.service.AuthService;

import jakarta.validation.Valid;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import org.springframework.security.core.Authentication;
import java.util.Map;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    @PostMapping("/register")
    public ResponseEntity<RegisterResponse> register(
            @Valid @RequestBody RegisterRequest request) {

        User user = authService.register(
                request.fullName(),
                request.email(),
                request.password()
        );

        RegisterResponse response = new RegisterResponse(
                user.getId(),
                user.getFullName(),
                user.getEmail(),
                user.getRole().name()
        );

        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }
    @PostMapping("/login")
public ResponseEntity<LoginResponse> login(
        @Valid @RequestBody LoginRequest request) {

    String token = authService.login(
            request.email(),
            request.password()
    );

    LoginResponse response = new LoginResponse(token, "Bearer");

    return ResponseEntity.ok(response);
}
@GetMapping("/me")
public Map<String, String> me(Authentication authentication) {
    return Map.of(
        "email", authentication.getName(),
        "message", "You are authenticated"
    );
}
@GetMapping("/verify-email")
public ResponseEntity<String> verifyEmail(
        @RequestParam("token") String token) {

    authService.verifyEmail(token);

    return ResponseEntity.ok(
            "Email verified successfully! You can now log in."
    );
}
}
