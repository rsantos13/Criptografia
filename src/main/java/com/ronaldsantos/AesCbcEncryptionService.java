package com.ronaldsantos;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

public class AesCbcEncryptionService implements EncryptionService {
    private static final int IV_SIZE = 16; // 128 bits
    private static final int HMAC_SIZE = 32; // 256 bits

    private final SecretKey encryptionKey;
    private final SecretKey hmacKey;

    private final ThreadLocal<Cipher> cipherThreadLocal = ThreadLocal.withInitial(() -> {
        try {
            return Cipher.getInstance("AES/CBC/PKCS5Padding");
        } catch (NoSuchPaddingException | NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    });

    private final ThreadLocal<Mac> macThreadLocal = ThreadLocal.withInitial(() -> {
        try {
            return Mac.getInstance("HmacSHA256");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    });

    public AesCbcEncryptionService(KeyManager keyManager) {
        this.encryptionKey = keyManager.getEncryptionKey();
        this.hmacKey = keyManager.getHmacKey();
    }

    @Override
    public String encrypt(String data) throws Exception {
        Cipher cipher = cipherThreadLocal.get();
        Mac mac = macThreadLocal.get();

        byte[] iv = new byte[IV_SIZE];
        SecureRandom random = new SecureRandom();
        random.nextBytes(iv);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        cipher.init(Cipher.ENCRYPT_MODE, encryptionKey, ivSpec);

        byte[] encryptedData = cipher.doFinal(data.getBytes(StandardCharsets.UTF_8));

        // Combina IV e texto cifrado
        byte[] ivAndEncryptedData = new byte[iv.length + encryptedData.length];
        System.arraycopy(iv, 0, ivAndEncryptedData, 0, iv.length);
        System.arraycopy(encryptedData, 0, ivAndEncryptedData, iv.length, encryptedData.length);

        // Calcula HMAC
        mac.init(hmacKey);
        byte[] hmac = mac.doFinal(ivAndEncryptedData);

        // Combina tudo
        byte[] finalData = new byte[ivAndEncryptedData.length + hmac.length];
        System.arraycopy(ivAndEncryptedData, 0, finalData, 0, ivAndEncryptedData.length);
        System.arraycopy(hmac, 0, finalData, ivAndEncryptedData.length, hmac.length);

        return Base64.getEncoder().encodeToString(finalData);
    }

    @Override
    public String decrypt(String encryptedData) throws Exception {
        Cipher cipher = cipherThreadLocal.get();
        Mac mac = macThreadLocal.get();

        byte[] allData = Base64.getDecoder().decode(encryptedData);

        if (allData.length < IV_SIZE + HMAC_SIZE) {
            throw new IllegalArgumentException("Dados inválidos ou corrompidos.");
        }

        byte[] iv = new byte[IV_SIZE];
        byte[] ivAndEncryptedData = new byte[allData.length - HMAC_SIZE];
        byte[] hmacReceived = new byte[HMAC_SIZE];

        System.arraycopy(allData, 0, iv, 0, IV_SIZE);
        System.arraycopy(allData, 0, ivAndEncryptedData, 0, ivAndEncryptedData.length);
        System.arraycopy(allData, ivAndEncryptedData.length, hmacReceived, 0, HMAC_SIZE);

        // Calcula HMAC
        mac.init(hmacKey);
        byte[] hmacCalculated = mac.doFinal(ivAndEncryptedData);

        if (!MessageDigest.isEqual(hmacReceived, hmacCalculated)) {
            throw new SecurityException("HMAC inválido. Os dados podem ter sido alterados.");
        }

        byte[] encryptedDataBytes = new byte[ivAndEncryptedData.length - IV_SIZE];
        System.arraycopy(ivAndEncryptedData, IV_SIZE, encryptedDataBytes, 0, encryptedDataBytes.length);

        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        cipher.init(Cipher.DECRYPT_MODE, encryptionKey, ivSpec);

        byte[] decryptedData = cipher.doFinal(encryptedDataBytes);

        return new String(decryptedData, StandardCharsets.UTF_8);
    }
}
