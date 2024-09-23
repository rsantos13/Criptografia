package com.ronaldsantos;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

public class AesGcmEncryptionService implements EncryptionService {
    private static final int IV_SIZE = 12; // 96 bits
    private static final int TAG_SIZE = 128; // 128 bytes
    private final SecretKey encryptionKey;

    // Usando ThreadLoca para evitarpr problemas de thread-safety com Cipher
    private final ThreadLocal<Cipher> cipherThreadLocal = ThreadLocal.withInitial(() -> {
        try {
            return Cipher.getInstance("AES/GCM/NoPadding");
        } catch (NoSuchPaddingException | NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    });

    public AesGcmEncryptionService(KeyManager keyManager) {
        this.encryptionKey = keyManager.getEncryptionKey();
    }

    @Override
    public String encrypt(String data) throws Exception {
        Cipher cipher = cipherThreadLocal.get();

        byte[] iv = new byte[IV_SIZE];
        SecureRandom random = new SecureRandom();
        random.nextBytes(iv);
        GCMParameterSpec spec = new GCMParameterSpec(TAG_SIZE, iv);

        cipher.init(Cipher.ENCRYPT_MODE, encryptionKey, spec);

        byte[] encryptedData = cipher.doFinal(data.getBytes(StandardCharsets.UTF_8));

        // Combina IV e texto cifrado
        byte[] ivAndEncryptedData = new byte[iv.length + encryptedData.length];
        System.arraycopy(iv, 0, ivAndEncryptedData, 0, iv.length);
        System.arraycopy(encryptedData, 0, ivAndEncryptedData, iv.length, encryptedData.length);

        return Base64.getEncoder().encodeToString(ivAndEncryptedData);
    }

    @Override
    public String decrypt(String encryptedData) throws Exception {
        Cipher cipher = cipherThreadLocal.get();

        byte[] ivAndEncryptedData = Base64.getDecoder().decode(encryptedData);

        byte[] iv = new byte[IV_SIZE];
        byte[] actualEncryptedData = new byte[ivAndEncryptedData.length - IV_SIZE];

        System.arraycopy(ivAndEncryptedData, 0, iv, 0, IV_SIZE);
        System.arraycopy(ivAndEncryptedData, IV_SIZE, actualEncryptedData, 0, actualEncryptedData.length);

        GCMParameterSpec spec = new GCMParameterSpec(TAG_SIZE, iv);

        cipher.init(Cipher.DECRYPT_MODE, encryptionKey, spec);

        byte[] decryptedData = cipher.doFinal(actualEncryptedData);

        return new String(decryptedData, StandardCharsets.UTF_8);
    }
}
