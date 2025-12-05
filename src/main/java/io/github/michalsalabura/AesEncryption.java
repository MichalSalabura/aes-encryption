package io.github.michalsalabura;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Scanner;

public class AesEncryption {
    public SecretKey generateKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        SecureRandom random = new SecureRandom();
        keyGenerator.init(128, random);
        SecretKey key = keyGenerator.generateKey();
        return key;
    }

    public String decodeKey(SecretKey key) {
        return Base64.getEncoder().encodeToString(key.getEncoded());
    }

    public SecretKey validateKey(String key) {
        if(key == null || key.trim().isEmpty()) {
            System.out.println("No key provided");
            return null;
        }
        try {
            key = key.trim();
            byte[] keyBytes = Base64.getDecoder().decode(key);

            int keyLength = keyBytes.length * 8;
            if(keyLength != 128) {
                System.out.println("Invalid key length");
                return null;
            }

            return new SecretKeySpec(keyBytes, "AES");

        } catch (IllegalArgumentException e) {
            System.out.println("Invalid key");
            return null;
        }
    }

    public boolean isCorrectKey(File encryptedFile, SecretKey key) {
        try {
            String cipherText = "";
            try (Scanner fileScanner = new Scanner(encryptedFile)) {
                while (fileScanner.hasNextLine()) {
                    cipherText += fileScanner.nextLine().trim();
                }
            } catch (FileNotFoundException e) {
                System.out.println("File not found!");
                return false;
            }

            byte[] combined = Base64.getDecoder().decode(cipherText);

            byte[] ivBytes = new byte[16];
            System.arraycopy(combined, 0, ivBytes, 0, ivBytes.length);
            IvParameterSpec ivParameterSpec = new IvParameterSpec(ivBytes);

            byte[] encrypted = new byte[combined.length - 16];
            System.arraycopy(combined, 16, encrypted, 0, encrypted.length);
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, key, ivParameterSpec);
            cipher.doFinal(encrypted);

            return true;
        } catch (BadPaddingException e) {
            System.out.println("Wrong key");
            return false;
        } catch (NoSuchPaddingException e) {
            throw new RuntimeException(e);
        } catch (IllegalBlockSizeException e) {
            throw new RuntimeException(e);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (InvalidAlgorithmParameterException e) {
            throw new RuntimeException(e);
        } catch (InvalidKeyException e) {
            System.out.println("Invalid key");
            return false;
        }
    }

    public boolean encryptFile(File file, SecretKey key, String newPath) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        File newFile =  new File(newPath);
        String originalContent = "";

        try {
            Scanner fileScanner = new Scanner(file);
            while (fileScanner.hasNextLine()) {
                String line = fileScanner.nextLine();
                originalContent +=  line + "\n";
            }
        } catch (FileNotFoundException e) {
            System.out.println("File not found: " + e.getMessage());
            return false;
        }

        byte[] contentBytes = originalContent.getBytes();

        byte[] ivBytes = new byte[16];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(ivBytes);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(ivBytes);

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key, ivParameterSpec);
        byte[] encrypted = cipher.doFinal(contentBytes);

        byte[] combined = new byte[ivBytes.length + encrypted.length];
        System.arraycopy(ivBytes, 0, combined, 0, ivBytes.length);
        System.arraycopy(encrypted, 0, combined, ivBytes.length, encrypted.length);

        String base64Text = Base64.getEncoder().encodeToString(combined);

        try (FileWriter writer = new FileWriter(newFile)) {
            writer.write(base64Text);
        } catch (IOException e) {
            System.out.println("Error writing file: " + e.getMessage());
            return false;
        }
        System.out.println("Encrypted!");
        return true;
    }

    public boolean decryptFile(File file, SecretKey key, String newPath) throws NoSuchPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, InvalidKeyException {
        File newFile = new File(newPath);
        String cipherText = "";

        try (Scanner fileScanner = new Scanner(file)) {
            while(fileScanner.hasNextLine()) {
                String line = fileScanner.nextLine().trim();
                cipherText +=  line;
            }
        } catch(FileNotFoundException e) {
            System.out.println("File not found: " + e.getMessage());
            return false;
        }
        byte[] combined = Base64.getDecoder().decode(cipherText);

        byte[] ivBytes = new byte[16];
        System.arraycopy(combined, 0, ivBytes, 0, ivBytes.length);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(ivBytes);

        byte[] encrypted = new byte[combined.length - 16];
        System.arraycopy(combined, 16, encrypted, 0, encrypted.length);

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, key, ivParameterSpec);
        byte[] decrypted = cipher.doFinal(encrypted);

        String decryptedContent = new String(decrypted);

        try(FileWriter writer = new FileWriter(newFile)) {
            writer.write(decryptedContent);
            System.out.println("File decrypted");
        } catch (IOException e) {
            System.out.println("Error writing File: " + e.getMessage());
            return false;
        }
        return true;
    }

}
