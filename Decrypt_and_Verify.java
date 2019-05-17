package cipherSuite;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.*;

/**
 * This class contains the decryption and verification operations
 */
class Decrypt_and_Verify {
    // the configuration variables for the class
    private Input.DecryptConfig config;
    private Input.User_input input;

    /**
     * This method creates a new decryption and verification suite according to the given parameters
     * @param config - the configuration object
     * @param input- the user input object
     */
    Decrypt_and_Verify(Input.DecryptConfig config, Input.User_input input) {
        this.config = config;
        this.input = input;
    }

    /**
     * This program decrypts a file according to its config file and checks its digital signature
     */
     void main() throws Exception {
        // parsing algorithm parameters
        AlgorithmParameters parameters = AlgorithmParameters.getInstance(config.symmetric_encryption_type);
        parameters.init(config.symmetric_parameters_encoded);

         // opening keystore
        try (FileInputStream keystore_loc = new FileInputStream(input.keystore_loc)){
            KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
            keystore.load(keystore_loc, input.pass.toCharArray());

            // decrypting and recreating symmetric key
            byte[] byte_symmetric_key = decrypt_key(keystore);
            SecretKey symmetric_key = new SecretKeySpec(byte_symmetric_key, 0, byte_symmetric_key.length, config.symmetric_encryption_type);

            // rebuilding the symmetric cipher
            Cipher decryption_cipher = Cipher.getInstance(config.symmetric_encryption_type + "/" + config.symmetric_encryption_mode + "/" + config.symmetric_padding_type, config.symmetric_encryption_provider);
            decryption_cipher.init(Cipher.DECRYPT_MODE, symmetric_key, parameters);

            // decrypting file
            decrypt_file(decryption_cipher);

            //verifying digital signature
            verify(keystore, input.dest, config, input.other_alias);
        }
    }

    /**
     * The function checks the digital signature against the hash with the senders public key
     * @param keystore - the Keystore that contains the sender's public key
     * @param dest - The decrypted file
     * @param config - The config object holding the config parameters
     * @param sender - The name of the entry containing the sender's public key
     * @throws Exception - IO or algorithm\provider not found exception
     */
    private void verify(KeyStore keystore, String dest, cipherSuite.Input.DecryptConfig config, String sender) throws Exception {
        // getting the public key
        PublicKey public_Key = keystore.getCertificate(sender).getPublicKey();

        // initializing the signature function with the public key
        Signature sign_function = Signature.getInstance(config.sign_type, config.sign_provider);
        sign_function.initVerify(public_Key);

        // calculating the decrypted file's hash
        byte [] hash = calc_hash(dest, config);
        sign_function.update(hash);

        // we check whether the digital signature is valid
        boolean verify = sign_function.verify(config.signed_hash);
        // the signature is valid and the decryption is complete
        if (verify) {
            System.out.println("The digital signature is valid and the file has been decrypted successfully");
        }
        // if the signature is invalid we output an error to console and to the decrypted file location
        else {
            System.out.println("The digital signature is invalid");
            try (FileOutputStream dest_stream = new FileOutputStream(dest)){
                dest_stream.write("The digital signature is invalid".getBytes());
            }
        }
    }

    /**
     * The function decrypts the file using the using the decrypted symmetric key
     * @param decryption_cipher - The decrypyion cipher which was loaded with the symmetric key
     * @throws Exception - An exception which indicates IO error
     */
    private void decrypt_file (Cipher decryption_cipher) throws Exception {
        // opening source and destination streams
        FileInputStream source_stream = new FileInputStream(input.source);
        try (        CipherInputStream cipher_stream = new CipherInputStream(source_stream, decryption_cipher);
                     FileOutputStream dest_stream = new FileOutputStream(input.dest)) {
            // we keep at all times only 8 bytes in memory in this array
            byte[] data = new byte[8];
            int state = cipher_stream.read(data);
            // decrypting data
            while (state != -1) {
                dest_stream.write(data,0,state);
                state = cipher_stream.read(data);
            }
        }
    }

    /**
     * This function decrypts the symmetric key using the receiver's private key
     * @param keystore - The keystore with the receiver's private key
     * @return key_cipher.doFinal(config.encrypted_symmetric_key) - the decrypted symmetric key
     * @throws Exception - An algorithm or provider not found exception
     */
    private byte[] decrypt_key (KeyStore keystore) throws Exception {
        // getting the private key
        PrivateKey private_key = (PrivateKey) keystore.getKey(input.my_alias, input.entry_pass.toCharArray());

        // creating the decryption cypher using the private key and decrypting
        Cipher key_cipher = Cipher.getInstance(config.asymmetric_encryption_type, config.asymmetric_encryption_provider);
        key_cipher.init(Cipher.DECRYPT_MODE, private_key);
        return key_cipher.doFinal(config.encrypted_symmetric_key);
    }

    /**
     * This function calculates the hash value of the original file
     * @param source - the original unencrypted file location
     * @param config - the config object holding the type and provider names of the hash function
     * @return hash_function.digest() - the hash value of the original file
     * @throws Exception - an exception which indicates that the algorithm or provider are not found, or some IO error
     */
    private byte[] calc_hash (String source, cipherSuite.Input.DecryptConfig config) throws Exception {
        // opening a file stream
        try (FileInputStream source_stream = new FileInputStream(source)){
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
}




