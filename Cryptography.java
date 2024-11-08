


/************************************************
 *               Mohsen Reyhani                 *
 *                 August 2024                  *
 *   Twitter: https://x.com/mohsenreyhani01     *
 *   Tel: https://t.me/exciton_missile_program  *
 *   Blog: https://mreyhani.wordpress.com       *
 *   Email: mohsen0reyhani@gmail.com            *
 *   Copyright © 2024 Mohsen Reyhani            *
 *          All rights reserved.                *
 ************************************************/


import android.security.keystore.KeyProperties;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Random;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;




public class Cryptography {


    private static final int _secure_key_array_size = 64;
    private static final int _salt_array_size = 64;
    private static final int _local_password_array_size = 64;

    private static char[] secure_key = new char[_secure_key_array_size];
    private static char[] salt = new char[_salt_array_size];
    private static char[] local_password = new char[_local_password_array_size];

    private static int secure_key_length = 0;
    private static int salt_length = 0;
    private static int local_password_length = 0;

    private static boolean Cryptography_parameters_readiness = false;

    private final static char[] _null = {'N','U','L','L'};
    private final static char[] _set_parameters = ("Set Parameters").toCharArray();

    public static char[] encryption(final char[] text_to_encryption) {


        if (Cryptography_parameters_readiness) {

            try {
/// PBEWithHmacSHA256AndAES_256
                SecretKeyFactory factory = SecretKeyFactory.getInstance("PBEwithHmacSHA384AndAES_256");
                KeySpec keySpec = new PBEKeySpec(secure_key, Auxiliary_Func.chars_to_bytes(salt),
                        10000, 256);
                SecretKey secretKey = factory.generateSecret(keySpec);
                SecretKeySpec secretKeySpec = new SecretKeySpec(secretKey.getEncoded(), KeyProperties.KEY_ALGORITHM_AES);

                Cipher cipher = Cipher.getInstance("AES/CBC/PKCS7Padding");

                byte[] initial_vector = new byte[cipher.getBlockSize()];
                SecureRandom randomSecureRandom = new SecureRandom();
                randomSecureRandom.nextBytes(initial_vector);
                IvParameterSpec ivParams = new IvParameterSpec(initial_vector);

                cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParams);

                byte[] encryption_byte_code = cipher.doFinal(Auxiliary_Func.chars_to_bytes(text_to_encryption));

                byte[] final_byte_code = new byte[initial_vector.length
                        + encryption_byte_code.length];

                System.arraycopy(initial_vector, 0, final_byte_code, 0, initial_vector.length);
                System.arraycopy(encryption_byte_code, 0, final_byte_code,
                        initial_vector.length, encryption_byte_code.length);

                return Base62.base62Encode(final_byte_code);

            } catch (Exception e) {
            //    Log.d("encryption","Error in encrypting: " + e);
            }

            return _null;

        } else {

            return _set_parameters;
        }
    }



    public static char[] decryption(final char[] text_to_decryption) {

        if (Cryptography_parameters_readiness) {

        try {

            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBEwithHmacSHA384AndAES_256");
            KeySpec keySpec = new PBEKeySpec(secure_key, Auxiliary_Func.chars_to_bytes(salt),
                    10000, 256);
            SecretKey secretKey = factory.generateSecret(keySpec);
            SecretKeySpec secretKeySpec = new SecretKeySpec(secretKey.getEncoded(), KeyProperties.KEY_ALGORITHM_AES);

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS7Padding");

            byte[] initial_bytes = Base62.base62Decode(text_to_decryption);

            byte[] initial_vector = new byte[cipher.getBlockSize()];

            if(initial_bytes.length > initial_vector.length) {

                System.arraycopy(initial_bytes, 0, initial_vector, 0, initial_vector.length);

                byte[] encrypted_message_bytes = new byte[initial_bytes.length - initial_vector.length];

                System.arraycopy(initial_bytes, initial_vector.length, encrypted_message_bytes, 0,
                        encrypted_message_bytes.length);

                IvParameterSpec ivParams = new IvParameterSpec(initial_vector);
                cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParams);

                byte[] final_byte_code = cipher.doFinal(encrypted_message_bytes);

                return Auxiliary_Func.bytes_to_chars(final_byte_code);

            } else return _null;


        } catch (Exception e) {
           // Log.d("decryption","Error in decrypting: " + e);
        }
        return _null;

        } else {

            return _set_parameters;
        }
    }


    public static RSA_Keys RSA_keys_generator()
    {

        try {

            KeyPairGenerator key_pair_generator;
            KeyPair key_pair;
            PublicKey publicKey;
            PrivateKey privateKey;
            RSA_Keys RSA_keys = new RSA_Keys();

            key_pair_generator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA);
            key_pair_generator.initialize(3072, new SecureRandom());
            key_pair = key_pair_generator.genKeyPair();

            publicKey = key_pair.getPublic();
            privateKey = key_pair.getPrivate();

            RSA_keys.put_publicKey(publicKey);
            RSA_keys.put_privateKey(privateKey);


            return RSA_keys;

        } catch (Exception e) {
         //   Log.d("RSA_keys_generator","Error in RSA keys generator: " + e);
        }

        return null;

    }


    public static char[] RSA_encryption(final char[] text_to_encryption, final PublicKey publicKey) {

        try {

            Cipher cipher;
            cipher = Cipher.getInstance(KeyProperties.KEY_ALGORITHM_RSA);
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);

            byte[] final_bytes = cipher.doFinal
                    (Auxiliary_Func.chars_to_bytes(text_to_encryption));

            char[] final_chars = Base62.base62Encode(final_bytes);

            return final_chars;

        }
        catch (Exception e)
        {
          //  Log.d("RSA_encryption","Error in RSA encryption: " + e);
        }

        return _null;

    }


    public static char[] RSA_decryption(final char[] text_to_decryption, final PrivateKey privateKey)  {

        try {

            Cipher cipher = Cipher.getInstance(KeyProperties.KEY_ALGORITHM_RSA);
            cipher.init(Cipher.DECRYPT_MODE, privateKey);

            byte[] initial_bytes = Base62.base62Decode(text_to_decryption);

            byte[] final_bytes = cipher.doFinal(initial_bytes);
            return StandardCharsets.UTF_8.decode(ByteBuffer.wrap(final_bytes)).array();


        }
        catch (Exception e)
        {
         //   Log.d("RSA_decryption","Error in RSA decryption: " + e);
        }

        return _null;

    }

    public static PublicKey public_key_from_chars(final char[] public_key_chars)
    {
        try {

        byte[] public_key_bytes = Base62.base62Decode(public_key_chars);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(public_key_bytes);

            KeyFactory key_factory = KeyFactory.getInstance(KeyProperties.KEY_ALGORITHM_RSA);
        PublicKey public_key = key_factory.generatePublic(keySpec);

        return public_key;

        }
        catch (Exception e)
        {
       //     Log.d("public_key_from_string","Error in generate public key from string: " + e);

            return null;
        }

    }

    public static PrivateKey private_key_from_chars(final char[] private_key_chars)
    {
        try {

            byte[] private_key_bytes = Base62.base62Decode(private_key_chars);
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(private_key_bytes);
            KeyFactory key_factory = KeyFactory.getInstance(KeyProperties.KEY_ALGORITHM_RSA);
            PrivateKey private_key = key_factory.generatePrivate(keySpec);

            return private_key;

        }
        catch (Exception e)
        {
       //     Log.d("private_key_from_string","Error in generate private key from string: " + e);

            return null;
        }

    }

    public static char[] public_key_to_chars(final PublicKey public_key) {

        try {

        byte[] public_key_byte = public_key.getEncoded();
        char[] public_key_chars = Base62.base62Encode(public_key_byte);

        return public_key_chars;

        }
        catch (Exception e)
        {
         //   Log.d("public_key_to_string","Error in generate public key to string: " + e);

            return _null;
        }

    }


    public static char[] private_key_to_chars(final PrivateKey private_key) {

        try {

            byte[] private_key_byte = private_key.getEncoded();
            char[] private_key_chars = Base62.base62Encode(private_key_byte);

            return private_key_chars;

        }
        catch (Exception e)
        {
        //    Log.d("private_key_to_string","Error in generate private key to string: " + e);

            return _null;
        }

    }


    public static char[] SHA384_hash(final char[] password) {

            try {
                MessageDigest messageDigest = MessageDigest.getInstance("SHA-384");

                byte[] bytes = messageDigest.digest(Auxiliary_Func.chars_to_bytes(password));

                StringBuilder sb = new StringBuilder();

                for (byte aByte : bytes) {
                    sb.append(Integer.toString((aByte & 0xff) + 0x100, 16).substring(1));
                }

                char[] generated_password = new char[sb.length()];

                sb.getChars(0, sb.length(), generated_password, 0);

                return generated_password;

            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            }
            return _null;

    }


    public static void secure_key_salt_generator(final int secure_key_salt_length, final char[] secure_key_salt) {

        String combination_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890!@#$*&%^";

        int combination_char_length = combination_chars.length();

        int random = 0;

        for(int i=0; i < secure_key_salt_length; i++)
        {
            random = new Random().nextInt(combination_char_length);
            secure_key_salt[i] = combination_chars.charAt(random);
        }

    }



    public static char[] generate_salt_from_password(final char[] password) // It may be pointless in terms of encryption technique, but it is useful for my application
    {

        byte[] password_bytes = Auxiliary_Func.chars_to_bytes(password);
        byte[] password_bytes_reverse = new byte[password_bytes.length];
        byte[] final_bytes = new byte[password_bytes_reverse.length];

        char [] characters = {'@','7','!','5','8','$','2','0','*','9','%','^',
                '1','3','&','%','4','A','W','R','O','X','?','z','C','Q','L','~','i','P','m','V','D','F' //34
                ,'j','U','K',')','Z','p','f','q','k','(','w','H',']','T','S','g','h','[','N','s','t','p','n','I','x','J','u','Y','y','r'};

        byte[] bitwise = (Character.toString(characters[password.length])).getBytes(StandardCharsets.UTF_8);


        for (int i = (password_bytes.length -1); i >= 0; i--)
        {

            password_bytes_reverse [(password_bytes.length - 1) - i] = password_bytes[i];
        }

        int p = password_bytes_reverse.length - (password_bytes_reverse.length % bitwise.length);

        int i=0;

        while (i < password_bytes_reverse.length) {

            if (i < p) {
                for (int j = 0; j < bitwise.length; j++) {

                    final_bytes[i + j] = (byte) (password_bytes_reverse[i + j] ^ bitwise[j]);
                }

            i = i + bitwise.length;

        } else {

                System.arraycopy(password_bytes_reverse, i, final_bytes, i, password_bytes_reverse.length - i);
            }
        }

        char[] final_chars = Base62.base62Encode(final_bytes);

        return SHA384_hash(final_chars);

    }



    public static void set_secure_key(final char[] secure_key) {

        secure_key_length = Math.min(_secure_key_array_size, secure_key.length);

        int i = 0;

        while (i < _secure_key_array_size)
        {

            if(i < secure_key_length)
                Cryptography.secure_key[i] = secure_key[i];
            else Cryptography.secure_key[i] = '\u0000';

            i++;
        }

    }


    public static void set_salt(final char[] salt) {

        salt_length = Math.min(_salt_array_size, salt.length);

        int i = 0;

        while (i < _salt_array_size)
        {

            if(i < salt_length)
                Cryptography.salt[i] = salt[i];
            else Cryptography.salt[i] = '\u0000';

            i++;
        }

    }


    public static void set_local_password(final char[] local_password) {

        local_password_length = Math.min(_local_password_array_size, local_password.length);

        int i = 0;

        while (i < _local_password_array_size) {
            if (i < local_password_length)
                Cryptography.local_password[i] = local_password[i];
            else Cryptography.local_password[i] = '\u0000';

            i++;
        }

    }



    public static void set_secure_key(final int secure_key_size, final char[] secure_key) {

       secure_key_length = Math.min(_secure_key_array_size, secure_key_size);

        int i = 0;

        while (i < _secure_key_array_size)
        {

            if(i < secure_key_length)
            Cryptography.secure_key[i] = secure_key[i];
            else Cryptography.secure_key[i] = '\u0000';

            i++;
        }

    }


    public static void set_salt(final int salt_size, final char[] salt) {

        salt_length = Math.min(_salt_array_size, salt_size);

        int i = 0;

        while (i < _salt_array_size)
        {

            if(i < salt_length)
                Cryptography.salt[i] = salt[i];
            else Cryptography.salt[i] = '\u0000';

            i++;
        }

    }


    public static void set_local_password(final int local_password_size, final char[] local_password) {

        local_password_length = Math.min(_local_password_array_size, local_password_size);

        int i = 0;

        while (i < _local_password_array_size)
        {
            if(i < local_password_length)
                Cryptography.local_password[i] = local_password[i];
            else Cryptography.local_password[i] = '\u0000';

            i++;
        }

    }


    public static char[] get_secure_key() {

        char[] secure_key = new char[secure_key_length];

        System.arraycopy(Cryptography.secure_key, 0, secure_key, 0, secure_key_length);

        return secure_key;

    }

    public static char[] get_salt() {

        char[] salt = new char[salt_length];

        System.arraycopy(Cryptography.salt, 0, salt, 0, salt_length);

        return salt;

    }


    public static char[] get_local_password() {

        char[] local_password = new char[local_password_length];

        System.arraycopy(Cryptography.local_password, 0, local_password, 0, local_password_length);

        return local_password;

    }

    public static void set_parameters_readiness() {

        char[] secure_key = Cryptography.get_secure_key();
        char[] salt = Cryptography.get_salt();

        if(secure_key.length > 0 && salt.length > 0) {

            if (secure_key[0] != '\u0000' && salt[0] != '\u0000') {

                Cryptography_parameters_readiness = true;

            } else Cryptography_parameters_readiness = false;

        }  else Cryptography_parameters_readiness = false;

    }

}
