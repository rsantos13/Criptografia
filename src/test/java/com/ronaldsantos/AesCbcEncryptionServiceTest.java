package com.ronaldsantos;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;

public class AesCbcEncryptionServiceTest {

    private EncryptionService encryptionService;

    @BeforeEach
    public void setUp() throws Exception {
        KeyManager keyManager = new KeyManagerImpl();
        encryptionService = new AesCbcEncryptionService(keyManager);
    }

    @Test
    public void testEncryptionDecryption() throws Exception {
        String originalData = "Este é um texto para testar criptografia AES CBC com HMAC.";
        String encryptedData = encryptionService.encrypt(originalData);

        assertNotNull(encryptedData);
        assertNotEquals(originalData, encryptedData);

        String decryptedData = encryptionService.decrypt(encryptedData);

        assertNotNull(decryptedData);
        assertEquals(originalData, decryptedData);
    }

    @Test
    public void testTamperedData() throws Exception {
        String originalData = "Texto original";
        String encryptedData = encryptionService.encrypt(originalData);

        // Modifica os dados criptografados
        byte[] encryptedBytes = Base64.getDecoder().decode(encryptedData);
        encryptedBytes[encryptedBytes.length - 1] ^= 1; // Inverte o último bit
        String tamperedEncryptedData = Base64.getEncoder().encodeToString(encryptedBytes);

        // Tenta descriptografar os dados adulterados
        assertThrows(SecurityException.class, () -> {
            encryptionService.decrypt(tamperedEncryptedData);
        });
    }
}
