package com.learnwithiftekhar.redissessionmanagement.dto.response;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
@AllArgsConstructor
public class TokenPair {
    private String accessToken;
    private String refreshToken;
    private long accessTokenExpirationMs;
    private long refreshTokenExpirationMs;
}
