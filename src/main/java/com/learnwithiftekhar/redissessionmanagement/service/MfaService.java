package com.learnwithiftekhar.redissessionmanagement.service;

import com.learnwithiftekhar.redissessionmanagement.dto.request.MfaConfirmRequest;
import com.learnwithiftekhar.redissessionmanagement.dto.response.MfaSetupResponse;
import com.learnwithiftekhar.redissessionmanagement.model.User;
import com.learnwithiftekhar.redissessionmanagement.repository.UserRepository;
import com.learnwithiftekhar.redissessionmanagement.util.TotpUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

@Service
@RequiredArgsConstructor
public class MfaService {
    private final UserRepository userRepository;
    private final TotpUtil totpUtil;
    private final EncryptionService encryptionService;

    // 1. MFA Setup
    // 2. First time Verification to confirm MFA
    // 3. MFA Verification for Login

    public MfaSetupResponse setupMfa(String username) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        // Query the database to check if the user exist
        User user = userRepository.findByUsername(username)
                .orElseThrow(
                        () -> new UsernameNotFoundException("User not found")
                );

        // 1. Check if mfa is already enabled
        if(user.isMfaEnabled()) {
            throw new IllegalStateException("MFA already enabled for user");
        }

        // Generate the secret key and save (not yet enabled)
        String rawSecret = totpUtil.generateSecret();
        String encryptedSecret = encryptionService.encrypt(rawSecret);

        user.setMfaSecret(encryptedSecret);
        userRepository.save(user);

        String otpAuthUri = totpUtil.buildOtpAuthUri(username, rawSecret);

        String qrCode = totpUtil.generateQRCodeBase64(otpAuthUri);

        return MfaSetupResponse.builder()
                .secret(rawSecret)
                .qrCodeUri(otpAuthUri)
                .qrCodeImage(qrCode)
                .build();
    }

    public boolean confirmMfa(
            String username,
            MfaConfirmRequest confirmRequest) {

        User user = userRepository.findByUsername(username)
                .orElseThrow(
                        () -> new UsernameNotFoundException("User not found")
                );

        if(user.isMfaEnabled()) {
            throw new RuntimeException("MFA already enabled for user");
        }

        if(user.getMfaSecret() == null) {
            throw new RuntimeException("MFA secret not set for user");
        }

        String decryptedSecret = encryptionService.decrypt(user.getMfaSecret());

        if(!totpUtil.verifyCode(decryptedSecret, confirmRequest.getCode())) {
            throw new RuntimeException("Invalid MFA code");
        }

        user.setMfaEnabled(true);
        userRepository.save(user);
        return true;
    }
}
