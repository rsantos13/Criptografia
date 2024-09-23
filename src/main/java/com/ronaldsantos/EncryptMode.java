package com.ronaldsantos;

public enum EncryptMode {
    AES_CGM("AES/GCM/NoPadding"),
    AES_CBC("AES/CBC/PKCS5Padding"),;

    EncryptMode(String transformation) {}
}
