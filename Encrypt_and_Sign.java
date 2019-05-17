package cipherSuite;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.io.*;
import java.security.*;
import java.util.Base64;

/**
 * This class contains the encryption and signing operations
 */
class Encrypt_and_Sign {
    // the configuration variables for the class
    private Input.EncryptConfig config;
    private Input.User_input input;

    /**
     * This method creates a new encryption and signing suite according to the given parameters
     * @param config - the configuration object
     * @param input- the user input object
     */
    Encrypt_and_Sign(Input.EncryptConfig config, Input.User_input input) {
        this.config = config;
        this.input = input;
    }

    /**
     * This program encrypts a file according to its specified constants and signs it
     */
    void main() throws Exception {
        // we generate a key for the encryption operation
        KeyGenerator key_generator = KeyGenerator.getInstance(config.symmetric_key_generator_type, config.symmetric_key_generator_provider);
        SecretKey secret_key = key_generator.generateKey();

        // we generate an IV
        IvParameterSpec iv = new IvParameterSpec(iv_num());

        // creating the encryption cipher
        Cipher cipher = Cipher.getInstance(config.symmetric_encryption_type + "/" + config.symmetric_encryption_mode + "/" + config.symmetric_padding_type, config.symmetric_encryption_provider);
        cipher.init(Cipher.ENCRYPT_MODE, secret_key, iv);

        // we encrypt and write the message and retrieve its hash
        byte[] hash = calc_hash();
        encrypt(cipher);

        // retrieving keystore from file
        try (FileInputStream keystore_stream = new FileInputStream(input.keystore_loc)) {
            KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
            keystore.load(keystore_stream, input.pass.toCharArray());

            // creating the config file for decryption
            config(keystore, hash, secret_key, cipher);

            // printing completion message
            System.out.println("Encryption and Signing completed successfully");
        }
    }

    /**
     * This function encrypts a symmetric key
     * @param keystore   - The keystore that contains a public key
     * @param secret_key - The symmetric key we wish to encrypt
     * @return config_cipher.doFinal(secret_key.getEncoded ()) - The encrypted key in byte array
     * @throws Exception an exception which indicates that the algorithm or provider are not found
     */
    private byte[] encrypt_key(KeyStore keystore, SecretKey secret_key) throws Exception {
        // getting the public key
        PublicKey pub = keystore.getCertificate(input.other_alias).getPublicKey();

        // encrypting using the public key (asymmetric encryption)
        Cipher config_cipher = Cipher.getInstance(config.asymmetric_encryption_type, config.asymmetric_encryption_provider);
        config_cipher.init(Cipher.ENCRYPT_MODE, pub);
        return config_cipher.doFinal(secret_key.getEncoded());
    }

    /**
     * The function creates a digital signature using the original files hash and the users private key
     * @param keystore - The key store that contains the users private key
     * @param hash     - The original files hash
     * @return sign_function.sign() - the digital signature
     * @throws Exception -  an exception which indicates that the algorithm or provider are not found
     */
    private byte[] sign(KeyStore keystore, byte[] hash) throws Exception {
        // getting private key from keystore
        PrivateKey private_key = (PrivateKey) keystore.getKey(input.my_alias, input.entry_pass.toCharArray());

        // signing the hash using the private key
        Signature sign_function = Signature.getInstance(config.sign_type, config.sign_provider);
        sign_function.initSign(private_key);
        sign_function.update(hash);
        return sign_function.sign();
    }

    /**
     * This function encrypts a file according to a given cypher and saves it at the specified destination
     * @param cipher - The encryption Cipher
     * @throws Exception - an exception which indicates that there is some IO error
     */
    private void encrypt(Cipher cipher) throws Exception {
        try (
                // opening file streams
                FileInputStream source_stream = new FileInputStream(input.source);
                CipherInputStream cipher_stream = new CipherInputStream(source_stream, cipher);
                FileOutputStream dest_stream = new FileOutputStream(input.dest)
        ) {
            // we keep at all times only 8 bytes in memory in this array
            byte[] data = new byte[8];
            int state = cipher_stream.read(data);
            // encrypting data
            while (state != -1) {
                dest_stream.write(data, 0, state);
                state = cipher_stream.read(data);
            }
        }
    }

    /**
     * This function calculates the hash value of the original file
     * @return hash_function.digest() - the hash value of the original file
     * @throws Exception - an exception which indicates that the algorithm or provider are not found, or some IO error
     */
    private byte[] calc_hash() throws Exception {
        // opening a file stream
        try (FileInputStream source_stream = new FileInputStream(input.source)) {
            // creating hash function
            MessageDigest hash_function = MessageDigest.getInstance(config.hash_type, config.hash_provider);

            // we keep at all times only 8 bytes in memory in this array
            byte[] data = new byte[8];
            int state = source_stream.read();
            // calculating hash
            while (state != -1) {
                hash_function.update(data);
                state = source_stream.read(data);
            }
            // after the entire message has been proceed we finalize the hash
            return hash_function.digest();
        }
    }

    /**
     * This function creates a pseudo-random IV number using Cryptographic pseudo-random generators
     * @return iv - the generated pseudo-random IV
     * @throws Exception - an exception which indicates that the algorithm or provider are not found
     */
    private byte[] iv_num() throws Exception {
        SecureRandom generator = SecureRandom.getInstance(config.random_number_gen_type, config.random_number_gen_provider);
        // creates an array of iv_size which is defined according to the algorithm which we use in the encryption
        byte[] iv = new byte[config.iv_size];
        generator.nextBytes(iv);
        return iv;
    }

    /**
     * This function creates the config file to be used in decryption
     * @param keystore   - The keystore that houses the private and public keys
     * @param hash-      The hash of the original file
     * @param secret_key - The key for the symmetric encryption
     * @param cipher     - The cipher for the symmetric encryption
     * @throws Exception - an exception which indicates some error in writing to the config file
     */
    private void config(KeyStore keystore, byte[] hash, SecretKey secret_key, Cipher cipher) throws Exception {
        // creating the digital signature
        final byte[] signed_hash = sign(keystore, hash);

        // we encrypt the symmetric key
        byte[] encrypted_symmetric_key = encrypt_key(keystore, secret_key);

        // we get the parameters for the symmetric encryption
        AlgorithmParameters symmetric_parameters = cipher.getParameters();
        byte[] symmetric_parameters_encoded = symmetric_parameters.getEncoded();

        // we write to the config file
        output_config(encrypted_symmetric_key, symmetric_parameters_encoded, signed_hash);
    }

    /**
     * This function writes to the config file
     * @param encrypted_symmetric_key      - The encrypted symmetric key in byte array form
     * @param symmetric_parameters_encoded - The encoded parametares for the Symmetric encryption
     * @param signed_hash                  - The signed hash
     * @throws Exception - an exception which indicates some error in writing to the config file
     */
    private void output_config(byte[] encrypted_symmetric_key, byte[] symmetric_parameters_encoded, final byte[] signed_hash) throws Exception {
        // creating config file
        File config_dest = new File(input.dest + "_configDEC.txt");
        try (
                FileWriter writer = new FileWriter(config_dest);
                BufferedWriter b_writer = new BufferedWriter(writer)
                ){
            Base64.Encoder encoder = Base64.getEncoder();

            // writing config elements for the symmetric encryption
            b_writer.write(encoder.encodeToString(encrypted_symmetric_key));
            b_writer.newLine();
            b_writer.write(encoder.encodeToString(symmetric_parameters_encoded));
            b_writer.newLine();

            // writing config elements for the authentication process
            b_writer.write(encoder.encodeToString(signed_hash));
            b_writer.newLine();

            // writing symmetric encryption specifications to config file
            b_writer.write(config.symmetric_encryption_type);
            b_writer.newLine();
            b_writer.write(config.symmetric_encryption_mode);
            b_writer.newLine();
            b_writer.write(config.symmetric_padding_type);
            b_writer.newLine();
            b_writer.write(config.symmetric_encryption_provider);
            b_writer.newLine();

            // writing signing specifications to config file
            b_writer.write(config.sign_type);
            b_writer.newLine();
            b_writer.write(config.sign_provider);
            b_writer.newLine();

            // writing asymmetric encryption specifications to config file
            b_writer.write(config.asymmetric_encryption_type);
            b_writer.newLine();
            b_writer.write(config.asymmetric_encryption_provider);
            b_writer.newLine();

            // writing hash specifications to config file
            b_writer.write(config.hash_type);
            b_writer.newLine();
            b_writer.write(config.hash_provider);
            b_writer.newLine();
        }
    }
}