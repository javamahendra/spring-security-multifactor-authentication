package com.learnwithiftekhar.redissessionmanagement.dto.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.Setter;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

@Setter
@Getter
@Builder
@AllArgsConstructor
public class AuthenticationResponse {
    private String accessToken;
    private String refreshToken;
    private String mfaToken;
    private boolean mfaRequired;
    private boolean mfaVerified;
}
