package com.learnwithiftekhar.redissessionmanagement.dto.request;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class MfaConfirmRequest {

    @NotBlank(
        message = "MFA code cannot be blank"
    )
    @Pattern(
        regexp = "\\d{6}",
        message = "MFA code must be a valid 6-digit code"
    )
    private String code;
}
