package io.github.michalsalabura;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import java.io.File;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Scanner;

public class Main {
    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        String choice = "";
        File providedFile = null;
        boolean running = true;

        AesEncryption aesEncryption = new AesEncryption();

        Scanner input = new Scanner(System.in);

        while (running) {

            System.out.println("What would you like to do?");
            System.out.println("1.Encrypt a file");
            System.out.println("2.Decrypt a file");
            System.out.println("3.Quit");

            System.out.print("Input: ");
            choice = input.nextLine().trim();

            if(choice.equalsIgnoreCase("1") || choice.equalsIgnoreCase("encrypt")) {
                providedFile = getFile(input);
                if(providedFile != null) {
                    SecretKey randomKey = aesEncryption.generateKey();
                    aesEncryption.encryptFile(providedFile, randomKey, "ciphertext.txt");
                    System.out.println("Encryption key is: " + aesEncryption.decodeKey(randomKey));
                } else {
                    System.out.println("Operation cancelled");
                }

            } else if(choice.equalsIgnoreCase("2") || choice.equalsIgnoreCase("decrypt")) {
                providedFile = getFile(input);
                if(providedFile != null) {
                    System.out.println("Please provide a key: ");
                    String key = input.nextLine();
                    SecretKey randomKey = aesEncryption.validateKey(key);

                    if (randomKey != null && !aesEncryption.isCorrectKey(providedFile, randomKey)) {
                        randomKey = null;
                    }

                    while(randomKey == null) {
                        System.out.println("Please provide a valid key: ");
                        key = input.nextLine();
                        randomKey = aesEncryption.validateKey(key);
                        if (randomKey != null && !aesEncryption.isCorrectKey(providedFile, randomKey)) {
                            randomKey = null;
                        }
                    }

                    aesEncryption.decryptFile(providedFile, randomKey, "plaintext.txt");
                } else {
                    System.out.println("Operation cancelled");
                }

            } else if(choice.equalsIgnoreCase("3") || choice.equalsIgnoreCase("quit")) {
                running = false;
            } else {
                System.out.println("Please select a valid option");
            }
        }

        System.out.println("Goodbye!");
        input.close();
    }

    public static File getFile(Scanner input) {
        boolean testFile = false;
        String name = "";
        while (!testFile) {
            System.out.println("Please enter filename: (to cancel input 1)");
            name =  input.nextLine();
            if(name.equalsIgnoreCase("1")) {
                return null;
            }
            testFile = validateFile(name);
        }
        return new File(name);
    }

    public static boolean validateFile(String path) {
        boolean isValid = true;

        try {
            File testFile = new File(path);
            if(!testFile.exists()) {
                System.out.println("File does not exist");
                isValid = false;
            } else if(!testFile.isFile()) {
                System.out.println("Provided name is not a file");
                isValid = false;
            } else if(!testFile.canRead()) {
                System.out.println("File cannot be read");
                isValid = false;
            }
            if(!path.toLowerCase().endsWith(".txt")) {
                System.out.println("File must have a .txt extension");
                isValid = false;
            }
            return isValid;
        } catch (Exception e) {
            System.out.println("Invalid name");
            return false;
        }
    }
}