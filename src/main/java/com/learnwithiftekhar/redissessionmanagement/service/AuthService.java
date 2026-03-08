package com.learnwithiftekhar.redissessionmanagement.service;

import com.learnwithiftekhar.redissessionmanagement.dto.request.VerificationRequest;
import com.learnwithiftekhar.redissessionmanagement.dto.response.AuthenticationResponse;
import com.learnwithiftekhar.redissessionmanagement.dto.request.LoginRequest;
import com.learnwithiftekhar.redissessionmanagement.dto.request.RegistrationRequest;
import com.learnwithiftekhar.redissessionmanagement.dto.response.TokenPair;
import com.learnwithiftekhar.redissessionmanagement.model.User;
import com.learnwithiftekhar.redissessionmanagement.repository.TokenRepository;
import com.learnwithiftekhar.redissessionmanagement.repository.UserRepository;
import com.learnwithiftekhar.redissessionmanagement.security.JwtTokenProvider;
import com.learnwithiftekhar.redissessionmanagement.util.TotpUtil;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.UUID;

@Service
public class AuthService {

    private final AuthenticationManager authenticationManager;
    private final JwtTokenProvider jwtTokenProvider;
    private final UserDetailsService userDetailsService;
    private final TokenRepository tokenRepository;
    private final PasswordEncoder passwordEncoder;
    private final UserRepository userRepository;
    private final TotpUtil totpUtil;
    private final EncryptionService encryptionService;

    @Value("${jwt.expiration}")
    private long jwtExpirationMS;

    @Value("${jwt.refreshExpiration}")
    private long refreshTokenExpirationMS;


    public AuthService(AuthenticationManager authenticationManager, JwtTokenProvider jwtTokenProvider, UserDetailsService userDetailsService, TokenRepository tokenRepository, PasswordEncoder passwordEncoder, UserRepository userRepository, TotpUtil totpUtil, EncryptionService encryptionService) {
        this.authenticationManager = authenticationManager;
        this.jwtTokenProvider = jwtTokenProvider;
        this.userDetailsService = userDetailsService;
        this.tokenRepository = tokenRepository;
        this.passwordEncoder = passwordEncoder;
        this.userRepository = userRepository;
        this.totpUtil = totpUtil;
        this.encryptionService = encryptionService;
    }

    public AuthenticationResponse register(RegistrationRequest registraion) {

        // First check if the user already exist
        userRepository.findByUsername(registraion.getUsername())
                .ifPresent(user -> {
                    throw new RuntimeException("Username is already in use");
                });

        // Create new user
        User user = new User();
        user.setUsername(registraion.getUsername());
        user.setPassword(passwordEncoder.encode(registraion.getPassword()));
        user.setRole(registraion.getRole());

        userRepository.save(user);

        return authenticateUser(registraion.getUsername(), registraion.getPassword());

    }

    public AuthenticationResponse login(LoginRequest loginRequest) {
        return authenticateUser(loginRequest.getUsername(), loginRequest.getPassword());
    }

    private AuthenticationResponse authenticateUser(String username, String password) {
        // Authenticate the user
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        username,
                        password
                )
        );

        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));

        if(user.isMfaEnabled()) {
            // 1. Generate UUID
            String mfaToken = UUID.randomUUID().toString();

            // 2. Store it to redis cache
            tokenRepository.storeMfaToken(mfaToken, user.getUsername());
            // 3. Response
            return AuthenticationResponse
                    .builder()
                    .mfaRequired(true)
                    .mfaVerified(false)
                    .mfaToken(mfaToken)
                    .build();
        }

        // Set authentication in security context
        SecurityContextHolder.getContext().setAuthentication(authentication);

        // Generate JWT token pair (access + refresh)
        TokenPair tokenPair = jwtTokenProvider.generateTokenPair(authentication);

        // Store token in Redis
        UserDetails userDetails = (UserDetails) authentication.getPrincipal();

        tokenRepository.storeTokens(
                userDetails.getUsername(),
                tokenPair.getAccessToken(),
                tokenPair.getRefreshToken(),
                tokenPair.getAccessTokenExpirationMs(),
                tokenPair.getRefreshTokenExpirationMs()
        );

        return AuthenticationResponse.builder()
                .accessToken(tokenPair.getAccessToken())
                .refreshToken(tokenPair.getRefreshToken())
                .build();

    }

    public void logout() {
        // Get Current authenticated User
        var userDetails = (UserDetails) SecurityContextHolder.getContext().getAuthentication().getPrincipal();

        // Remove all tokens for this user
        tokenRepository.removeAllTokens(userDetails.getUsername());
    }

    public ResponseEntity<?> refreshToken(String refreshToken) {
        // Validate the refresh token
        if(!jwtTokenProvider.validateToken(refreshToken)) {
            return ResponseEntity.badRequest()
                    .body("Invalid refresh token");
        }

        // Check if token is blacklisted
        if(tokenRepository.isRefreshTokenBlacklisted(refreshToken)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body("ERROR: Refresh token is blacklisted");
        }


        // Extract the username from refresh token
        String username = jwtTokenProvider.getUsernameFromToken(refreshToken);


        // Verify token matches stored token for user
        String storedRefreshToken = tokenRepository.getRefreshToken(username);

        if(storedRefreshToken == null || !storedRefreshToken.equals(refreshToken)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body("ERROR: Invalid refresh token");
        }

        UserDetails userDetails = userDetailsService.loadUserByUsername(username);

        // Create new authentication object
        UsernamePasswordAuthenticationToken authToken =
                new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());


        String newAccessToken = jwtTokenProvider.generateAccessToken(authToken);

        // Update access token in Redis
        tokenRepository.removeAccessToken(username);
        tokenRepository.storeTokens(
                username,
                newAccessToken,
                refreshToken,
                jwtExpirationMS,
                refreshTokenExpirationMS
        );

        return ResponseEntity.ok(AuthenticationResponse.builder()
                .accessToken(newAccessToken)
                .refreshToken(refreshToken)
                .build());
    }

    public AuthenticationResponse verifyMfa(@Valid VerificationRequest verificationRequest) {
        String username = tokenRepository.getMfaToken(verificationRequest.getMfaToken());

        User user = userRepository.findByUsername(username)
                .orElseThrow(
                        () -> new UsernameNotFoundException("User not found with username: " + username)
                );

        if(!user.isMfaEnabled()) {
            throw new RuntimeException("MFA is not enabled for user: " + username);
        }

        if(user.getMfaSecret() == null) {
            throw new RuntimeException("MFA secret is not set for user: " + username);
        }

        String decryptedSecret = encryptionService.decrypt(user.getMfaSecret());
        // secret, code
        if(!totpUtil.verifyCode(decryptedSecret, verificationRequest.getCode())) {
            throw new RuntimeException("Invalid MFA code for user: " + username);
        }

        // 1. Authenticate the user
        UserDetails u = org.springframework.security.core.userdetails.User
                .withUsername(user.getUsername())
                .password(user.getPassword())
                .authorities(user.getRole().name())
                .build();

        Authentication auth = new UsernamePasswordAuthenticationToken(
                u,
                null,
                u.getAuthorities()
        );

        // 2. Generate the token pair
        TokenPair tokenPair = jwtTokenProvider.generateTokenPair(auth);

        // 3. Store the token in the redis
        tokenRepository.storeTokens(
                u.getUsername(),
                tokenPair.getAccessToken(),
                tokenPair.getRefreshToken(),
                tokenPair.getAccessTokenExpirationMs(),
                tokenPair.getRefreshTokenExpirationMs()
        );

        // 4. Remove the mfa token from redis
        tokenRepository.removeMfaToken(verificationRequest.getMfaToken());

        return AuthenticationResponse.builder()
                .accessToken(tokenPair.getAccessToken())
                .refreshToken(tokenPair.getRefreshToken())
                .mfaVerified(true)
                .mfaRequired(true)
                .build();
    }
}
