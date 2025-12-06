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

    /**
     * Generates a random 128-bit AES encryption key.
     *
     * @return SecretKey object containing the generated key
     * @throws NoSuchAlgorithmException if AES algorithm is not available
     */
    public SecretKey generateKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        SecureRandom random = new SecureRandom();
        keyGenerator.init(128, random);
        SecretKey key = keyGenerator.generateKey();
        return key;
    }

    /**
     * Converts a SecretKey to Base64 string representation without padding.
     *
     * @param key the SecretKey to encode
     * @return Base64-encoded string of the key without padding characters
     */
    public String decodeKey(SecretKey key) {
        String textKey = Base64.getEncoder().encodeToString(key.getEncoded());
        return textKey.substring(0, textKey.length()-2);
    }

    /**
     * Validates and converts a Base64 string to a SecretKey.
     * Checks for correct format, length, and absence of padding.
     *
     * @param key Base64 string representation of the key
     * @return SecretKey object if valid, null otherwise
     */
    public SecretKey validateKey(String key) {
        if(key == null || key.trim().isEmpty()) {
            System.out.println("No key provided");
            return null;
        }
        if(key.endsWith("=")) {
            System.out.println("Invalid key provided");
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

    /**
     * Verifies if the provided key can successfully decrypt the encrypted file.
     * Attempts decryption without saving the result.
     *
     * @param encryptedFile the file containing encrypted data
     * @param key the SecretKey to test
     * @return true if the key is correct, false otherwise
     */
    public boolean isCorrectKey(File encryptedFile, SecretKey key) {
        // Read encrypted file content
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

            // Extract IV from first 16 bytes
            byte[] ivBytes = new byte[16];
            System.arraycopy(combined, 0, ivBytes, 0, ivBytes.length);
            IvParameterSpec ivParameterSpec = new IvParameterSpec(ivBytes);

            // Extract encrypted data
            byte[] encrypted = new byte[combined.length - 16];
            System.arraycopy(combined, 16, encrypted, 0, encrypted.length);

            // Decrypt
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

    /**
     * Encrypts a file using AES encryption with CBC mode.
     * The encrypted data is saved as Base64 text with the IV prepended.
     *
     * @param file the file to encrypt
     * @param key the encryption key
     * @param newPath the path where the encrypted file will be saved
     * @return true if encryption successful, false otherwise
     */
    public boolean encryptFile(File file, SecretKey key, String newPath) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        File newFile =  new File(newPath);
        String originalContent = "";

        // Read file content
        try (Scanner fileScanner = new Scanner(file)){
            while (fileScanner.hasNextLine()) {
                String line = fileScanner.nextLine();
                originalContent +=  line + "\n";
            }
        } catch (FileNotFoundException e) {
            System.out.println("File not found: " + e.getMessage());
            return false;
        }
        byte[] contentBytes = originalContent.getBytes();

        // Get random IV
        byte[] ivBytes = new byte[16];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(ivBytes);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(ivBytes);

        // Encrypt the data
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key, ivParameterSpec);
        byte[] encrypted = cipher.doFinal(contentBytes);

        // Combine encrypted data with IV
        byte[] combined = new byte[ivBytes.length + encrypted.length];
        System.arraycopy(ivBytes, 0, combined, 0, ivBytes.length);
        System.arraycopy(encrypted, 0, combined, ivBytes.length, encrypted.length);

        // Encode to Base64
        String base64Text = Base64.getEncoder().encodeToString(combined);

        // Write to a new file
        try (FileWriter writer = new FileWriter(newFile)) {
            writer.write(base64Text);
            writer.flush();
        } catch (IOException e) {
            System.out.println("Error writing file: " + e.getMessage());
            return false;
        }
        return true;
    }

    /**
     * Decrypts a file that was encrypted using the encryptFile method.
     * Expects Base64-encoded data with IV prepended.
     *
     * @param file the encrypted file to decrypt
     * @param key the decryption key
     * @param newPath the path where the decrypted file will be saved
     * @return true if decryption successful, false otherwise
     */
    public boolean decryptFile(File file, SecretKey key, String newPath) throws NoSuchPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, InvalidKeyException {
        File newFile = new File(newPath);
        String cipherText = "";

        // Read content from provided file
        try (Scanner fileScanner = new Scanner(file)) {
            while(fileScanner.hasNextLine()) {
                String line = fileScanner.nextLine().trim();
                cipherText += line;
            }
        } catch(FileNotFoundException e) {
            System.out.println("File not found: " + e.getMessage());
            return false;
        }
        byte[] combined = Base64.getDecoder().decode(cipherText);

        // Extract IV from encrypted data
        byte[] ivBytes = new byte[16];
        System.arraycopy(combined, 0, ivBytes, 0, ivBytes.length);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(ivBytes);

        // Extract data without IV
        byte[] encrypted = new byte[combined.length - 16];
        System.arraycopy(combined, 16, encrypted, 0, encrypted.length);

        // Decrypt the data
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, key, ivParameterSpec);
        byte[] decrypted = cipher.doFinal(encrypted);

        String decryptedContent = new String(decrypted);

        // Write data to a new file
        try(FileWriter writer = new FileWriter(newFile)) {
            writer.write(decryptedContent);
            writer.flush();
        } catch (IOException e) {
            System.out.println("Error writing File: " + e.getMessage());
            return false;
        }
        return true;
    }

}