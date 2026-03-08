package com.learnwithiftekhar.redissessionmanagement.dto.request;

import com.learnwithiftekhar.redissessionmanagement.model.Role;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@AllArgsConstructor
public class RegistrationRequest {
    private String username;
    private String password;

    @Enumerated(EnumType.STRING)
    private Role role;
}
