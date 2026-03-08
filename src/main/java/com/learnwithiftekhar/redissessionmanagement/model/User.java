package com.learnwithiftekhar.redissessionmanagement.model;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;
import org.hibernate.annotations.DynamicUpdate;

@Entity
@Table(name = "users")
@Setter
@Getter
@DynamicUpdate
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private String username;
    private String password;

    @Enumerated(EnumType.STRING)
    private Role role;

    @Column(
            name = "mfa_enabled",
            columnDefinition = "boolean default false"
    )
    private boolean mfaEnabled;

    @Column(
            name = "mfa_secret"
    )
    private String mfaSecret;

}
