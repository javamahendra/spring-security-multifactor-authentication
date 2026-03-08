package com.learnwithiftekhar.redissessionmanagement.dto.request;

import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
@AllArgsConstructor
public class RefreshTokenRequest {
    @NotBlank
    private String refreshToken;
}
