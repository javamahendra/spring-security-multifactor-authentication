package com.learnwithiftekhar.redissessionmanagement.controller;

import com.learnwithiftekhar.redissessionmanagement.dto.request.MfaConfirmRequest;
import com.learnwithiftekhar.redissessionmanagement.dto.response.MfaSetupResponse;
import com.learnwithiftekhar.redissessionmanagement.service.AuthService;
import com.learnwithiftekhar.redissessionmanagement.service.MfaService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;

@RestController
@RequestMapping("/api/mfa")
@RequiredArgsConstructor
public class MfaController {
    private final MfaService mfaService;
    private final AuthService authService;

    @PostMapping("/setup")
    public ResponseEntity<MfaSetupResponse> setupMFA(Principal principal) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        MfaSetupResponse response = mfaService.setupMfa(principal.getName());
        return ResponseEntity.ok(response);
    }

    @PostMapping("/confirm")
    public ResponseEntity<String> confirmMfa(
            Principal principal,
            @Valid @RequestBody MfaConfirmRequest confirmRequest
    ) {
        boolean confirmed = mfaService.confirmMfa(principal.getName(), confirmRequest);

        if(!confirmed) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body("Invalid MFA Code");
        }

        authService.logout();

        return ResponseEntity.ok("MFA confirmed successfully");
    }
}
