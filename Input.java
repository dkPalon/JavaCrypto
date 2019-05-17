package cipherSuite;

import java.io.BufferedReader;
import java.util.Base64;

/**
 * A utility class that hold classes that service the Encrypt_and_Sign and Decrypt_and_Verify classes
 */
class Input {

    /**
     * An object class used to hold the encryption config data
     */
    static class EncryptConfig {
        // definition for the symmetric encryption
        String symmetric_encryption_type;
        String symmetric_encryption_mode;
        String symmetric_padding_type;
        String symmetric_encryption_provider;
        int iv_size;

        // definition for the asymmetric encryption
        String asymmetric_encryption_type;
        String asymmetric_encryption_provider;

        // definition for the random number generator
        String random_number_gen_type;
        String random_number_gen_provider;

        // definition for the hash function
        String hash_type;
        String hash_provider;

        // definition for the sign function
        String sign_type;
        String sign_provider;

        // symmetric key generator
        String symmetric_key_generator_type;
        String symmetric_key_generator_provider;

        /**
         * This constructor creates the config object which holds all relevant config data
         * @param config_file - The config file
         * @throws Exception - An exception which indicates an IO error
         */
        EncryptConfig(BufferedReader config_file) throws Exception {
            // definition for the symmetric encryption
            symmetric_encryption_type = config_file.readLine();
            symmetric_encryption_mode = config_file.readLine();
            symmetric_padding_type = config_file.readLine();
            symmetric_encryption_provider = config_file.readLine();
            iv_size = Integer.parseInt(config_file.readLine());

            // definition for the asymmetric encryption
            asymmetric_encryption_type = config_file.readLine();
            asymmetric_encryption_provider = config_file.readLine();

            // definition for the random number generator
            random_number_gen_type = config_file.readLine();
            random_number_gen_provider = config_file.readLine();

            // definition for the hash function
            hash_type = config_file.readLine();
            hash_provider = config_file.readLine();

            // definition for the sign function
            sign_type = config_file.readLine();
            sign_provider = config_file.readLine();

            // symmetric key generator
            symmetric_key_generator_type = config_file.readLine();
            symmetric_key_generator_provider = config_file.readLine();
        }
    }

    /**
     * An object class used to hold the decryption config data
     */
    static class DecryptConfig {
        // data relating to the symmetric encryption
        byte[] encrypted_symmetric_key;
        byte[] symmetric_parameters_encoded;
        String symmetric_encryption_type;
        String symmetric_encryption_mode;
        String symmetric_padding_type;
        String symmetric_encryption_provider;

        // data relating to the sign function
        String sign_type;
        String sign_provider;
        byte[] signed_hash;

        // data relating to the asymmetric encryption
        String asymmetric_encryption_type;
        String asymmetric_encryption_provider;

        // data relating to the hash function
        String hash_type;
        String hash_provider;

        /**
         * This constructor creates the config object which holds all relevant config data
         * @param config_file - The config file
         * @throws Exception - An exception which indicates an IO error
         */
        DecryptConfig(BufferedReader config_file) throws Exception {
            // retrieving the config elements

            // decoding byte based entities
            Base64.Decoder decoder = Base64.getDecoder();
            encrypted_symmetric_key = decoder.decode(config_file.readLine());
            symmetric_parameters_encoded = decoder.decode(config_file.readLine());
            signed_hash = decoder.decode(config_file.readLine());

            // definition for the symmetric encryption
            symmetric_encryption_type = config_file.readLine();
            symmetric_encryption_mode = config_file.readLine();
            symmetric_padding_type = config_file.readLine();
            symmetric_encryption_provider = config_file.readLine();

            // definition for the sign function
            sign_type = config_file.readLine();
            sign_provider = config_file.readLine();

            // definition for the asymmetric encryption
            asymmetric_encryption_type = config_file.readLine();
            asymmetric_encryption_provider = config_file.readLine();

            // definition for the hash function
            hash_type = config_file.readLine();
            hash_provider = config_file.readLine();
        }
    }

    /**
     * An object class used to hold the user input
     */
    static class User_input {
        String source;
        String dest;
        String keystore_loc;
        String pass;
        String my_alias;
        String other_alias;
        String entry_pass;

        /**
         * This function constructs a new Input object which holds the parsed input from the command line
         * @param args - the command line arguments to be parsed
         */
        User_input(String[] args) {
            // parsing all input args
            source = args[0];
            dest = args[1];
            keystore_loc = args[2];
            pass = args[3];
            my_alias = args[4];
            other_alias = args[5];
            entry_pass = args[6];
        }
    }
}
