package io.github.michalsalabura;

import java.util.Scanner;

public class Main {
    public static void main(String[] args) {
        String choice = "";
        String filePath = "";
        boolean running = true;

        Scanner input = new Scanner(System.in);

        while (running) {

            System.out.println("What would you like to do?");
            System.out.println("1.Encrypt a file");
            System.out.println("2.Decrypt a file");
            System.out.println("3.Quit");

            System.out.print("Input: ");
            choice = input.nextLine();


            if(choice.equalsIgnoreCase("1") || choice.equalsIgnoreCase("encrypt")) {
                filePath = getPath(input);
                System.out.print("Encrypted a file: " + filePath);
                System.out.println(choice);
            } else if(choice.equalsIgnoreCase("2") || choice.equalsIgnoreCase("decrypt")) {
                filePath = getPath(input);
                System.out.print("Decrypted a file: " + filePath);
                System.out.println(choice);
            } else if(choice.equalsIgnoreCase("3") || choice.equalsIgnoreCase("quit")) {
                running = false;
            } else {
                System.out.println("Please select a valid option");
            }
        }
        System.out.println("Goodbye!");
        input.close();
    }
    public static String getPath(Scanner input) {
        String path = "";
        System.out.println("Please provide a name or a path to your file");
        path = input.nextLine();
        return path;
    }
}