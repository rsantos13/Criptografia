package com.ronaldsantos;

public interface EncryptService {
    String encrypt(String data) throws Exception;
    String decrypt(String data) throws Exception;
}
