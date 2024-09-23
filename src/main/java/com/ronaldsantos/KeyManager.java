package com.ronaldsantos;

import javax.crypto.SecretKey;

public interface KeyManager {
    SecretKey getEncryptionKey();
    SecretKey getHmacKey();
}
