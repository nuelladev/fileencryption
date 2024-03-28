package com.example.fileencryption.service;


import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.Base64;

@Service
public class FileEncryptionService {

    private static final String AES = "AES";
    private static final int KEY_SIZE = 128; // or 256 bits


    public String encrypt(String data, String key) throws Exception{
     Cipher cipher = Cipher.getInstance(AES);
     cipher.init(Cipher.ENCRYPT_MODE, generateKey(key));
     byte[] encryptedBytes = cipher.doFinal(data.getBytes());
     return Base64.getEncoder().encodeToString(encryptedBytes);
    }


    public String decrypt(String encryptedData, String key) throws Exception{
    Cipher cipher = Cipher.getInstance(AES);
    cipher.init(Cipher.DECRYPT_MODE, generateKey(key));
    byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedData));
    return new String(decryptedBytes);
    }


    private SecretKey generateKey(String key) throws Exception{
        KeyGenerator keyGenerator = KeyGenerator.getInstance(AES);
        SecureRandom secureRandom = new SecureRandom(key.getBytes());
        keyGenerator.init(KEY_SIZE, secureRandom);
        return new SecretKeySpec(keyGenerator.generateKey().getEncoded(), AES);
    }

}

