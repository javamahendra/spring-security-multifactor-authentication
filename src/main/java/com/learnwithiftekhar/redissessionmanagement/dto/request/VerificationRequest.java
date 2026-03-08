package com.learnwithiftekhar.redissessionmanagement.dto.request;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class VerificationRequest {

    @NotBlank(message = "MFA token cannot be blank")
    private String mfaToken;

    @NotBlank(
            message = "Verification code cannot be blank"
    )
    @Pattern(
            regexp = "\\d{6}",
            message = "Verification code must be a 6-digit number"
    )
    private String code;
}
