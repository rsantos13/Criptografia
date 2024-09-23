package com.ronaldsantos;

import org.junit.jupiter.api.Test;

import java.io.File;
import java.io.FileInputStream;
import java.util.Base64;
import java.util.Properties;

import static org.junit.jupiter.api.Assertions.*;

public class KeyManagerImplTest {

    @Test
    public void testKeyLoadingFromEnvironment() throws Exception {
        // Configura as variáveis de ambiente (somente para o teste)
        String encryptionKeyBase64 = "SuaChaveDeCriptografiaBase64";
        String hmacKeyBase64 = "SuaChaveHmacBase64";

        // Simula as variáveis de ambiente usando System Properties
        System.setProperty("ENCRYPTION_KEY", encryptionKeyBase64);
        System.setProperty("HMAC_KEY", hmacKeyBase64);

        KeyManager keyManager = new KeyManagerImpl();

        assertNotNull(keyManager.getEncryptionKey());
        assertNotNull(keyManager.getHmacKey());

        // Limpa as propriedades do sistema
        System.clearProperty("ENCRYPTION_KEY");
        System.clearProperty("HMAC_KEY");
    }

    @Test
    public void testKeyGenerationAndSaving() throws Exception {
        // Remove o arquivo de chaves se existir
        File keyFile = new File("keys.properties");
        if (keyFile.exists()) {
            keyFile.delete();
        }

        KeyManager keyManager = new KeyManagerImpl();

        assertNotNull(keyManager.getEncryptionKey());
        assertNotNull(keyManager.getHmacKey());

        // Verifica se o arquivo foi criado
        assertTrue(keyFile.exists());

        // Carrega as chaves do arquivo e verifica se são iguais às carregadas
        Properties properties = new Properties();
        try (FileInputStream fis = new FileInputStream(keyFile)) {
            properties.load(fis);
        }

        String encryptionKeyBase64 = properties.getProperty("ENCRYPTION_KEY");
        String hmacKeyBase64 = properties.getProperty("HMAC_KEY");

        assertNotNull(encryptionKeyBase64);
        assertNotNull(hmacKeyBase64);

        // Decodifica as chaves
        byte[] encryptionKeyBytes = Base64.getDecoder().decode(encryptionKeyBase64);
        byte[] hmacKeyBytes = Base64.getDecoder().decode(hmacKeyBase64);

        assertArrayEquals(encryptionKeyBytes, keyManager.getEncryptionKey().getEncoded());
        assertArrayEquals(hmacKeyBytes, keyManager.getHmacKey().getEncoded());
    }
}
