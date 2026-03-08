package com.learnwithiftekhar.redissessionmanagement.controller;

import com.learnwithiftekhar.redissessionmanagement.dto.request.LoginRequest;
import com.learnwithiftekhar.redissessionmanagement.dto.request.RefreshTokenRequest;
import com.learnwithiftekhar.redissessionmanagement.dto.request.RegistrationRequest;
import com.learnwithiftekhar.redissessionmanagement.dto.request.VerificationRequest;
import com.learnwithiftekhar.redissessionmanagement.dto.response.AuthenticationResponse;
import com.learnwithiftekhar.redissessionmanagement.service.AuthService;
import jakarta.validation.Valid;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;


@RestController
@RequestMapping("/api/auth")
@Slf4j
public class AuthController {

    private final AuthService authService;


    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    @PostMapping("/register")
    public ResponseEntity<?> registerNewUser(@Valid @RequestBody RegistrationRequest registrationRequest) {
        return ResponseEntity.ok(authService.register(registrationRequest));
    }

    @PostMapping("/login")
    public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {
        return ResponseEntity.ok(authService.login(loginRequest));
    }

    @PostMapping("/verify/mfa")
    public ResponseEntity<AuthenticationResponse> verifyMfa(
            @Valid @RequestBody VerificationRequest verificationRequest) {
        AuthenticationResponse response = authService.verifyMfa(verificationRequest);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logout() {
        authService.logout();
        return ResponseEntity.ok("You have been signed out");

    }
    @PostMapping("/refresh")
    public ResponseEntity<?> refreshToken(@Valid @RequestBody RefreshTokenRequest request) {
        String refreshToken = request.getRefreshToken();
        return authService.refreshToken(refreshToken);
    }
}
