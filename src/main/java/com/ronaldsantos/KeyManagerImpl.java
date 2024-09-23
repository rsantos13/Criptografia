package com.ronaldsantos;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Properties;

public class KeyManagerImpl implements  KeyManager {
    private static final int KEY_SIZE = 256; // Tamanho da chave em bits
    private static final String ENCRYPTION_KEY_ENV = "ENCRYPTION_KEY";
    private static final String HMAC_KEY_ENV = "HMAC_KEY";
    private static final String KEY_FILE = "keys.properties";

    private final SecretKey encryptionKey;
    private final SecretKey hmacKey;

    public KeyManagerImpl() throws Exception {
        SecretKey loadedEncryptionKey = null;
        SecretKey loadedHmacKey = null;

        // 1. Tenta carregar as chaves das variáveis de ambiente
        loadedEncryptionKey = loadKeyFromEnvironment(ENCRYPTION_KEY_ENV, "AES");
        loadedHmacKey = loadKeyFromEnvironment(HMAC_KEY_ENV, "HmacSHA256");

        // 2. Se as chaves não estiverem nas variáveis de ambiente, tenta carregar do arquivo
        if (loadedEncryptionKey == null || loadedHmacKey == null) {
            File keyFile = new File(KEY_FILE);
            if (keyFile.exists()) {
                Properties properties = new Properties();
                try (FileInputStream fis = new FileInputStream(keyFile)) {
                    properties.load(fis);
                }
                loadedEncryptionKey = loadKeyFromProperties(properties, ENCRYPTION_KEY_ENV, "AES");
                loadedHmacKey = loadKeyFromProperties(properties, HMAC_KEY_ENV, "HmacSHA256");
            }
        }

        // 3. Se as chaves ainda não foram carregadas, gera novas chaves e salva no arquivo
        if (loadedEncryptionKey == null || loadedHmacKey == null) {
            loadedEncryptionKey = generateKey("AES");
            loadedHmacKey = generateKey("HmacSHA256");

            // Salva as chaves no arquivo para uso futuro
            Properties properties = new Properties();
            properties.setProperty(ENCRYPTION_KEY_ENV, Base64.getEncoder().encodeToString(loadedEncryptionKey.getEncoded()));
            properties.setProperty(HMAC_KEY_ENV, Base64.getEncoder().encodeToString(loadedHmacKey.getEncoded()));
            try (FileOutputStream fos = new FileOutputStream(KEY_FILE)) {
                properties.store(fos, "Chaves criptográficas");
            }
        }

        this.encryptionKey = loadedEncryptionKey;
        this.hmacKey = loadedHmacKey;
    }

    @Override
    public SecretKey getEncryptionKey() {
        return encryptionKey;
    }

    @Override
    public SecretKey getHmacKey() {
        return hmacKey;
    }

    // Método para carregar a chave das variáveis de ambiente
    private SecretKey loadKeyFromEnvironment(String envVar, String algorithm) {
        String keyBase64 = System.getenv(envVar);
        if (keyBase64 != null && !keyBase64.isEmpty()) {
            byte[] keyBytes = Base64.getDecoder().decode(keyBase64);
            return new SecretKeySpec(keyBytes, algorithm);
        }
        return null;
    }

    // Método para carregar a chave do arquivo de propriedades
    private SecretKey loadKeyFromProperties(Properties properties, String keyName, String algorithm) {
        String keyBase64 = properties.getProperty(keyName);
        if (keyBase64 != null && !keyBase64.isEmpty()) {
            byte[] keyBytes = Base64.getDecoder().decode(keyBase64);
            return new SecretKeySpec(keyBytes, algorithm);
        }
        return null;
    }

    // Método para gerar uma nova chave
    private SecretKey generateKey(String algorithm) throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(algorithm);
        if (algorithm.equals("AES")) {
            keyGenerator.init(KeyManagerImpl.KEY_SIZE);
        } else if (algorithm.equals("HmacSHA256")) {
            // Para HmacSHA256, o tamanho da chave pode ser até 512 bits
            keyGenerator.init(KeyManagerImpl.KEY_SIZE);
        }
        return keyGenerator.generateKey();
    }
}
