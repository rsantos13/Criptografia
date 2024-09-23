package com.ronaldsantos;

public class Main {
    public static void main(String[] args) {
        try {
            KeyManager keyManager = new KeyManagerImpl();

            // Escolha o serviço de criptografia desejado
            EncryptionService encryptionService = new AesGcmEncryptionService(keyManager);
            // EncryptionService encryptionService = new AesCbcEncryptionService(keyManager);

            String originalData = "Dados sensíveis que precisam ser protegidos";

            // Criptografa
            String encryptedData = encryptionService.encrypt(originalData);
            System.out.println("Dados Criptografados: " + encryptedData);

            // Descriptografa
            String decryptedData = encryptionService.decrypt(encryptedData);
            System.out.println("Dados Descriptografados: " + decryptedData);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}