package com.learnwithiftekhar.redissessionmanagement.service;

import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

@Service
public class EncryptionService {

    private static final String ALGORITHM = "AES/GCM/NoPadding";
    private static final int IV_LENGTH_BYTE = 12;
    private static final int TAG_LENGTH_BIT = 128;
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    @Value("${app.security.encryption-key}")
    private String masterSecretKey;

    private SecretKey secretKey;

    @PostConstruct
    public void init() {
        if (masterSecretKey == null || masterSecretKey.isEmpty()) {
            throw new IllegalArgumentException("Encryption key cannot be null or empty");
        }

        byte[] decodedKey = Base64.getDecoder().decode(masterSecretKey);
        this.secretKey = new SecretKeySpec(decodedKey, "AES");
    }

    public String encrypt(String plainText) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        byte[] iv = new byte[IV_LENGTH_BYTE];
        SECURE_RANDOM.nextBytes(iv);

        cipher.init(Cipher.ENCRYPT_MODE, secretKey, new GCMParameterSpec(TAG_LENGTH_BIT, iv));
        byte[] cipherText = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));

        // Pack the data
        ByteBuffer byteBuffer = ByteBuffer.allocate(iv.length + cipherText.length);
        byteBuffer.put(iv);
        byteBuffer.put(cipherText);

        return Base64.getEncoder().encodeToString(byteBuffer.array());
    }

    public String decrypt(String encryptedText) {
        try {
            byte[] decodedBytes = Base64.getDecoder().decode(encryptedText);
            ByteBuffer byteBuffer = ByteBuffer.wrap(decodedBytes);

            byte[] iv = new byte[IV_LENGTH_BYTE];
            byteBuffer.get(iv);

            byte[] cipherText = new byte[byteBuffer.remaining()];
            byteBuffer.get(cipherText);

            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, new GCMParameterSpec(TAG_LENGTH_BIT, iv));

            byte[] plainTextByte = cipher.doFinal(cipherText);
            return new String(plainTextByte, StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new RuntimeException("Failed to decrypt text", e);
        }
    }
}
