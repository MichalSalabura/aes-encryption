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

        // Menu loop
        while (running) {
            System.out.println("What would you like to do?");
            System.out.println("1.Encrypt a file");
            System.out.println("2.Decrypt a file");
            System.out.println("3.Quit");

            System.out.print("Input: ");
            choice = input.nextLine().trim();

            // Handle encryption
            if(choice.equalsIgnoreCase("1") || choice.equalsIgnoreCase("encrypt")) {
                providedFile = getFile(input);
                if(providedFile != null) {
                    SecretKey randomKey = aesEncryption.generateKey();
                    if(aesEncryption.encryptFile(providedFile, randomKey, "ciphertext.txt")) {
                        System.out.println("Encryption key is: " + aesEncryption.decodeKey(randomKey));
                        System.out.println("Data from the file encrypted and saved in ciphertext.txt\n\n");
                    } else {
                        System.out.println("Data not encrypted\n\n");
                    }
                } else {
                    System.out.println("Operation cancelled\n\n");
                }

                // Handle decryption
            } else if(choice.equalsIgnoreCase("2") || choice.equalsIgnoreCase("decrypt")) {
                providedFile = getFile(input);
                if(providedFile != null) {
                    System.out.println("Please provide a key: (input 1 to cancel)");
                    String key = input.nextLine();

                    if(key.equalsIgnoreCase("1")) {
                        System.out.println("Operation cancelled\n\n");
                    } else {
                        SecretKey randomKey = aesEncryption.validateKey(key);

                        // Check if key is valid and correct
                        if (randomKey != null && !aesEncryption.isCorrectKey(providedFile, randomKey)) {
                            randomKey = null;
                        }

                        // Loop asking for a valid key
                        while(randomKey == null) {
                            System.out.println("Please provide a valid key: (input 1 to cancel)");
                            key = input.nextLine();

                            if(key.equalsIgnoreCase("1")) {
                                System.out.println("Operation cancelled\n\n");
                                break;
                            }

                            randomKey = aesEncryption.validateKey(key);
                            if (randomKey != null && !aesEncryption.isCorrectKey(providedFile, randomKey)) {
                                randomKey = null;
                            }
                        }

                        if(randomKey != null) {
                            if(aesEncryption.decryptFile(providedFile, randomKey, "plaintext.txt")) {
                                System.out.println("Data decrypted and saved in plaintext.txt\n\n");
                            } else {
                                System.out.println("Data not decrypted\n\n");
                            }
                        }
                    }

                } else {
                    System.out.println("Operation cancelled\n\n");
                }

                // Handle quit
            } else if(choice.equalsIgnoreCase("3") || choice.equalsIgnoreCase("quit")) {
                running = false;
            } else {
                System.out.println("\n\nPlease select a valid option");
            }
        }

        System.out.println("\n\nGoodbye!");
        input.close();
    }

    /**
     * Prompts the user to enter a filename and validates it.
     * Continues prompting until a valid file is provided or user cancels.
     *
     * @param input Scanner object for reading user input
     * @return File object if valid file provided, null if user cancels
     */
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

    /**
     * Validates that the provided path/name points to a readable .txt file.
     *
     * @param path the file path to validate
     * @return true if the file exists, is readable, and has .txt extension
     */
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