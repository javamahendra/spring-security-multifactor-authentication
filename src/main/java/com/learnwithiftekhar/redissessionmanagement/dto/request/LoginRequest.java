package com.learnwithiftekhar.redissessionmanagement.dto.request;

import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
@AllArgsConstructor
public class LoginRequest {

    @NotBlank
    private String username;

    @NotBlank
    private String password;

}
