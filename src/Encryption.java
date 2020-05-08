/*
This is encryption/decryption code
You can choose AES/DES/3DES algorithm
You can choose CBC/CTR mode.

Author: Korey Pecha
 */

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Scanner;

public class Encryption {

    private static IvParameterSpec THE_IV;
    private static SecretKeySpec SKS;
    private static byte[] preIV = new byte[0];
    private static String THE_KEY = "";

    public static void main(String[] args) throws Exception {

        // Ask user if they want to Encrypt or Decrypt.
        Scanner sc = new Scanner(System.in);
        System.out.println("Select encryption or decryption (1,2):\n1) Encryption\n2) Decryption");
        int edChoice = Integer.parseInt(sc.nextLine());

        // Ask user which encryption algorithm they wish to use.
        sc = new Scanner(System.in);
        System.out.println("Select an encryption algorithm (1,2,3):\n1) AES\n2) DES\n3) 3DES");
        int aChoice = Integer.parseInt(sc.nextLine());

        // Ask user which encryption mode they wish to use.
        sc = new Scanner(System.in);
        System.out.println("Select an encryption mode (1,2):\n1) CTR\n2) CBC");
        int mChoice = Integer.parseInt(sc.nextLine());

        // Initialize parameters.
        String algo = "";
        String mode = "";
        int theSize = 0;
        int tag = 0;

        // Define algorithm parameters based on user input.
        switch(aChoice){
            case 1:
                algo = "AES";
                theSize = 16;
                break;
            case 2:
                algo = "DES";
                theSize = 8;
                break;
            case 3:
                algo = "DESede";
                theSize = 8;
                tag = 24;
        }

        // Define mode parameters based on user input.
        switch(mChoice){
            case 1:
                mode = "CTR";
                break;
            case 2:
                mode = "CBC";
        }

        // Request encryption key from user.
        sc = new Scanner(System.in);
        System.out.print("Please enter the encryption key: ");
        THE_KEY = sc.nextLine();


        // The input file
        sc = new Scanner(System.in);
        System.out.print("Enter file name: ");
        String filename = sc.nextLine();

        // The output file
        sc = new Scanner(System.in);
        System.out.print("Enter output file name: ");
        String outfile = sc.nextLine();


        // Begin timer, begin execution
        long start = System.nanoTime();

        // Create file variable for reading
        File file = new File(filename);


        // Create the IV.
        ivMaker(theSize);


        // Create the hashed key.
        hashMaker(theSize,algo,tag);


        // Encrypt or decrypt based of edChoice (user input).
        if (edChoice == 1){
            String plaintext = null;
            String text;
            try {
                Scanner scan = new Scanner(file);
                plaintext = scan.nextLine();
                while (scan.hasNextLine()){
                    text = scan.nextLine();
                    plaintext = plaintext + "\r\n" + text;
                }
                byte result[] = Encrypt(plaintext,theSize,algo,mode);
                FileOutputStream fileOut = new FileOutputStream(outfile);
                fileOut.write(result);
            } catch (IOException e){
                e.printStackTrace();
                System.exit(0);
            }
        }

        else if (edChoice == 2) {
            try {
                byte[] encryptedMessage = readContentIntoByteArray(file);
                String revert = new String(Decrypt(encryptedMessage,theSize,algo,mode,tag));
                File files = new File(outfile);
                FileWriter fileWriter = new FileWriter(files, true);
                fileWriter.write(revert);
                fileWriter.flush();
                fileWriter.close();
            } catch (IOException e) {
                e.printStackTrace();
                System.exit(0);
            }
        }
        //Print completion statement
        System.out.println("Operation complete!");

        // End timer
        long end = System.nanoTime();
        double elapsedTime = (end - start) / 100000000;
        System.out.println("Runtime: " + elapsedTime + " seconds");

    }

    // Create Initialization vector.
    // Input = size of IV.
    public static void ivMaker(int size){

        preIV = new byte[size];
        SecureRandom random = new SecureRandom();
        random.nextBytes(preIV);
        THE_IV = new IvParameterSpec(preIV);
    }

    // Hash the key.
    // Input = plaintext key, size of hash, desired encryption algorithm.
    public static void hashMaker(int theSize, String algo, int tag) throws Exception{

        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(THE_KEY.getBytes("UTF-8"));
        byte[] keyToBytes = new byte[0];

        if(tag > 0){
            keyToBytes = new byte[tag];
        } else {
            keyToBytes = new byte[theSize];
        }

        System.arraycopy(md.digest(),0,keyToBytes,0,keyToBytes.length);

        SKS = new SecretKeySpec(keyToBytes,algo);
    }

    public static byte[] Encrypt(String plain, int theSize, String algo, String mode) throws Exception{

        byte[] cleanText = plain.getBytes();

        //Encrypt.
        Cipher cipher = Cipher.getInstance(algo+"/"+mode+"/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, SKS,THE_IV);
        byte[] cipherText = cipher.doFinal(cleanText);

        // Add IV to encryption.
        byte[] finalProduct = new byte[theSize+cipherText.length];
        System.arraycopy(preIV,0,finalProduct,0,theSize);
        System.arraycopy(cipherText,0,finalProduct,theSize,cipherText.length);

        return finalProduct;
    }

    public static byte[] Decrypt(byte[] ciphertext, int theSize, String algo, String mode, int tag) throws Exception{

        //IV extraction.
        byte[] iv = new byte[theSize];
        System.arraycopy(ciphertext,0,iv,0,theSize);
        THE_IV = new IvParameterSpec(iv);

        //Extract Encrypted Message.
        int messageLength = ciphertext.length - theSize;
        byte[] encryptedMessage = new byte[messageLength];
        System.arraycopy(ciphertext, theSize, encryptedMessage, 0, messageLength);

        //Hash function call.
        hashMaker(theSize,algo,tag);

        //Decrypt.
        Cipher cipher = Cipher.getInstance(algo+"/"+mode+"/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, SKS,THE_IV);
        byte[] decryption = cipher.doFinal(encryptedMessage);

        return decryption;
    }

    //Converts file into an array of bytes to use in PRGA
    private static byte[] readContentIntoByteArray(File file) {

        FileInputStream fileInputStream = null;
        byte[] bFile = new byte[(int) file.length()];
        try {
            // convert file into array of bytes
            fileInputStream = new FileInputStream(file);
            fileInputStream.read(bFile);
            fileInputStream.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return bFile;
    }
}
