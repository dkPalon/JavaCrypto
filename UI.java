package cipherSuite;

import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.security.*;
import java.util.Scanner;

/**
 * The user interface Class of the encryption/decryption software
 */
public class UI {

    /**
     * Main method of the encryption/decryption software, initializes and oversees all encryption/decryption operation
     * according to input
     * @param args - command line arguments from the user
     *             args[0] - defines the software operating mode
     *                       "E" means only encrypt
     *                       "D" means only decrypt
     *                       "ED" means encrypt and decrypt
     *             args[1] - location of config file
     *                       for "E" and "ED" modes it is the encryption config file
     *                       for "D" mode it is the decryption config file
     *             args[2] - The file to encrypt/decrypt
     *             args[3] - The destination for the encrypted/decrypted file
     *             args[4] - The name of the sender (to be used for entry lookup in key store)
     *             args[5] - The name of the receiver (to be used for entry lookup in key store)
     *             args[6] - for "ED" and "E" mode location of sender's key store, for "D" mode location of receiver keystore
     *             args[7] - for "ED" mode location of receiver keystore
     */
    public static void main(String[] args) {
        try (Scanner reader_input = new Scanner(System.in)){
            // parsing command line arguments
            String mode = args[0];
            String config_loc = args[1];
            String source = args[2];
            String dest = args[3];
            String sender = args[4];
            String receiver = args[5];
            String keystore_loc_sender = args[6];

            // parsing receiver keystore location according to mode
            String keystore_lcc_receiver = "";
            if (mode.equals("ED")) {
                keystore_lcc_receiver = args[7];
            }
            if (mode.equals("D")) {
                keystore_lcc_receiver = args[6];
            }

            String pass;
            String entry_pass;
            // encryption operation
            if (mode.equals("ED") || mode.equals("E")) {
                // password for keystore prompt
                System.out.println("Please Enter the Sender's KeyStore's password");
                pass = reader_input.nextLine();
                // password for keystore entry prompt
                System.out.println("Please Enter the KeyStore's Entry password for the Sender");
                entry_pass = reader_input.nextLine();

                // determining actual destination according to mode
                String eDest = dest;
                if (mode.equals("ED")) {
                    eDest = source + "EN.txt";
                }

                // configuring and executing encryption operation
                String[] args_en = {source, eDest, keystore_loc_sender, pass,sender, receiver, entry_pass};
                Input.User_input input_en = new Input.User_input(args_en);
                encrypt(config_loc, input_en);
            }
            // decryption operation
            if (mode.equals("ED") || mode.equals("D")) {
                // password for keystore prompt
                System.out.println("Please Enter the Receiver KeyStore's password");
                pass = reader_input.nextLine();
                // password for keystore entry prompt
                System.out.println("Please Enter the KeyStore's Entry password for the Receiver");
                entry_pass = reader_input.nextLine();

                // determining actual source according to mode
                String dSource = source;
                if (mode.equals("ED")) {
                    dSource = source + "EN.txt";
                }
                // determining actual config according to mode
                String dConfig_loc = config_loc;
                if (mode.equals("ED")) {
                    dConfig_loc = source + "EN.txt"+ "_configDEC.txt";
                }

                // configuring and executing decryption operation
                String[] args_dec = {dSource, dest, keystore_lcc_receiver, pass, receiver, sender, entry_pass};
                Input.User_input input_dec = new Input.User_input(args_dec);
                decrypt(dConfig_loc,input_dec);
            }
        }
        // calls error handle function
        catch (Exception e) {
            error_handle(e);
        }
    }

    /**
     * This method configures the encryption operation and executes it
     * @param config_loc - location of the config file
     * @param input_en - the user input for the encryption operation
     * @throws Exception - indicates error in encryption
     */
    private static void encrypt(String config_loc, Input.User_input input_en) throws Exception {
        File config_dest = new File(config_loc);
        try (FileReader reader = new FileReader(config_dest);
             BufferedReader config_file = new BufferedReader(reader)) {
            // creating configuration objects for the encryption
            Input.EncryptConfig encryptConfig = new Input.EncryptConfig(config_file);
            // building the encryption suite using the config variables and user input
            Encrypt_and_Sign encryption = new Encrypt_and_Sign(encryptConfig, input_en);

            // encrypting and signing
            encryption.main();
        }
    }

    /**
     * This method configures the decryption operation and executes it
     * @param decrypt_config - location of the config file
     * @param input_dec - the user input for the decryption operation
     * @throws Exception - indicates error in decryption
     */
    private static void decrypt(String decrypt_config, Input.User_input input_dec) throws Exception {
        File decrypt_config_dest = new File(decrypt_config);
        try (        FileReader reader_dec = new FileReader(decrypt_config_dest);
                     BufferedReader config_file_dec = new BufferedReader(reader_dec)){
            // creating configuration objects for the decryption
            cipherSuite.Input.DecryptConfig decryptConfig = new cipherSuite.Input.DecryptConfig(config_file_dec);
            // building the decryption suite using the config variables and user input
            Decrypt_and_Verify decryption = new Decrypt_and_Verify(decryptConfig, input_dec);

            // decryption and verifying
            decryption.main();
        }
    }

    /**
     * This function handles errors and prints their reason
     * @param e - the error that we got
     */
    private static void error_handle (Exception e) {
        if (e instanceof ArrayIndexOutOfBoundsException) {
            System.out.println("wrong number of arguments was given");
        } else {
            if (e instanceof NoSuchAlgorithmException) {
                System.out.println("Invalid Algorithm was given in config");
            } else {
                if (e instanceof NoSuchProviderException) {
                    System.out.println("Invalid Algorithm was provider given in config");
                } else {
                    if (e instanceof FileNotFoundException) {
                        System.out.println("One of the specified file location is invalid");
                    } else {
                        if (e instanceof KeyStoreException) {
                            System.out.println("Error accessing keystore");
                        } else {
                            if (e instanceof IOException) {
                                System.out.println("Bad input was given, check that passwords are correct");
                            } else {
                                if (e instanceof SignatureException) {
                                    System.out.println("Error during signing processes");
                                } else {
                                    if (e instanceof NoSuchPaddingException) {
                                        System.out.println("Specified padding constant doesn't exists");
                                    }
                                    else {
                                        if (e instanceof KeyException) {
                                            System.out.println("Bad key was used");
                                        }
                                        else {
                                            if (e instanceof UnrecoverableKeyException) {
                                                System.out.println("Problem getting key from key store");
                                            }
                                            else {
                                                System.out.println("The program has encountered an unspecified error");
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

        }
    }
}
