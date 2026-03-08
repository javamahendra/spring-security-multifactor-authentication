package com.learnwithiftekhar.redissessionmanagement.repository;

import jakarta.validation.constraints.NotBlank;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Repository;

import java.util.concurrent.TimeUnit;

@Repository
public class TokenRepository {
    private final RedisTemplate<String, Object> redisTemplate;

    // Key prefixes for token storage
    private static final String ACCESS_TOKEN_KEY_PREFIX = "user:access:";
    private static final String REFRESH_TOKEN_KEY_PREFIX = "user:refresh:";

    // Key prefixes for token blacklisting
    private static final String ACCESS_BLACKLIST_PREFIX = "blacklist:access:";
    private static final String REFRESH_BLACKLIST_PREFIX = "blacklist:refresh:";
    private static final String MFA_PENDING_PREFIX = "mfa_pending:";

    @Value("${jwt.expiration}")
    private long jwtExpirationMS;

    @Value("${jwt.refreshExpiration}")
    private long refreshTokenExpirationMS;

    @Value("${app.mfaTokenExpiration}")
    private long mfaTokenExpiration;

    @Autowired
    public TokenRepository(RedisTemplate<String, Object> redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    /**
     * Store both access and refresh tokens for a user
     */

    public void storeTokens(String username,
                            String accessToken,
                            String RefreshToken,
                            long accessTokenExpiration,
                            long refreshTokenExpiration) {
        // Store access token
        String accessKey = ACCESS_TOKEN_KEY_PREFIX + username;
        redisTemplate.opsForValue().set(accessKey, accessToken);
        redisTemplate.expire(accessKey, accessTokenExpiration, TimeUnit.MILLISECONDS);


        // Store refresh token
        String refreshKey = REFRESH_TOKEN_KEY_PREFIX + username;
        redisTemplate.opsForValue().set(refreshKey, RefreshToken);
        redisTemplate.expire(refreshKey, refreshTokenExpiration, TimeUnit.MILLISECONDS);
    }

    /**
     * Retrieve access token for a user
     */
    public String getAccessToken(String username) {
        String accessKey = ACCESS_TOKEN_KEY_PREFIX + username;
        return getToken(accessKey);
    }


    /**
     * Retrieve refresh token for a user
     */
    public String getRefreshToken(String username) {
        String refreshKey = REFRESH_TOKEN_KEY_PREFIX + username;
        return getToken(refreshKey);
    }

    private String getToken(String accessKey) {
        Object accessToken = redisTemplate.opsForValue().get(accessKey);
        return accessToken != null ? accessToken.toString() : null;
    }

    /**
     * Remove all tokens for a user (complete logout)
     */
    public void removeAllTokens(String username) {
        String accessToken = getAccessToken(username);
        String refreshToken = getRefreshToken(username);

        // Remove Tokens
        String accessKey = ACCESS_TOKEN_KEY_PREFIX + username;
        String refreshKey = REFRESH_TOKEN_KEY_PREFIX + username;

        redisTemplate.delete(accessKey);
        redisTemplate.delete(refreshKey);

        // Blacklist tokens if they exist
        if(accessToken != null) {
            blacklistAccessToken(accessToken, jwtExpirationMS);
        }
        if(refreshToken != null) {
            blacklistRefreshToken(refreshToken, refreshTokenExpirationMS);
        }
    }

    /**
     * Remove just the access token used for token refresh scenarios
     */
    public void removeAccessToken(String username) {
        String accessToken = getAccessToken(username);
        String accessKey = ACCESS_TOKEN_KEY_PREFIX + username;
        redisTemplate.delete(accessKey);

        // Blacklist the access token
        if(accessToken != null) {
            blacklistAccessToken(accessToken, jwtExpirationMS);
        }
    }

    /**
     * Blacklist an accessToken
     */
    public void blacklistAccessToken(String accessToken, long expirationTimeInMillis) {
        String key = ACCESS_BLACKLIST_PREFIX + accessToken;
        redisTemplate.opsForValue().set(key, "blacklisted");
        redisTemplate.expire(key, expirationTimeInMillis, TimeUnit.MILLISECONDS);
    }

    /**
     * Blacklist a refresh token
     */
    public void blacklistRefreshToken(String refreshToken, long expirationTimeInMillis) {
        String key = REFRESH_BLACKLIST_PREFIX + refreshToken;
        redisTemplate.opsForValue().set(key, "blacklisted");
        redisTemplate.expire(key, expirationTimeInMillis, TimeUnit.MILLISECONDS);
    }

    /**
     * Check if an access token is blacklisted
     */
    public boolean isAccessTokenBlacklisted(String token) {
        String key = ACCESS_BLACKLIST_PREFIX + token;
        return Boolean.TRUE.equals(redisTemplate.hasKey(key));
    }

    /**
     * Check if a refresh token is blacklisted
     */
    public boolean isRefreshTokenBlacklisted(String token) {
        String key = REFRESH_BLACKLIST_PREFIX + token;
        return Boolean.TRUE.equals(redisTemplate.hasKey(key));
    }

    public void storeMfaToken(String mfaToken, String username) {
        String accessKey = MFA_PENDING_PREFIX + mfaToken;
        redisTemplate.opsForValue().set(accessKey, username);

        redisTemplate.expire(accessKey, mfaTokenExpiration, TimeUnit.MILLISECONDS);

    }

    public String getMfaToken(@NotBlank(message = "MFA token cannot be blank") String mfaToken) {
        String accessKey = MFA_PENDING_PREFIX + mfaToken;
        return getToken(accessKey);
    }

    public void removeMfaToken(@NotBlank(message = "MFA token cannot be blank") String mfaToken) {
        String accessKey = MFA_PENDING_PREFIX + mfaToken;
        redisTemplate.delete(accessKey);
    }
}
