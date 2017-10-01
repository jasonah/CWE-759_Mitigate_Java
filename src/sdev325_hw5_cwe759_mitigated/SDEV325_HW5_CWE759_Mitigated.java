/*
 * JASON HOWARTH
 * SDEV325 6380
 * 16 JULY 2017
 * HOMEWORK 5: Mitigated CWE-759 (Use of a One-Way Hash without a Salt)
 * File: SDEV325_HW5_CWE759_Mitigated.java
 */
package sdev325_hw5_cwe759_mitigated;

import java.util.*;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.PBEKeySpec;


import java.security.SecureRandom;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.SecretKeyFactory;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

public class SDEV325_HW5_CWE759_Mitigated {
           
    public static void main(String[] args) {

        Scanner input = new Scanner(System.in);

        //Tell user to create a username
        System.out.print("Create an account. Enter a username: ");
        //Store username
        String inputUsername = input.next();

        //Tell user to create a password
        System.out.print("\nEnter a password: ");
        
        //Store password in Char Array
        char[] inputPasswordCharArray = input.next().toCharArray();

        //MITIGATED CWE-759 VULNERABILITY: Creates a random salt, then hashes the password with the random salt
        
        //Generate a random salt
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[24];
        random.nextBytes(salt);
        
        try {
            //Hash password with salt prefix (Code from OWASP: https://www.owasp.org/index.php/Hashing_Java)
            SecretKeyFactory skf = SecretKeyFactory.getInstance( "PBKDF2WithHmacSHA512" );
            PBEKeySpec spec = new PBEKeySpec( inputPasswordCharArray, salt, 10000, 192 );
            SecretKey key = skf.generateSecret( spec );
            byte[] hashedSaltedPassword = key.getEncoded( );
            
            //Convert salt bytes to hexadecimal
            StringBuffer saltHexString = new StringBuffer();
            for (int i=0;i<salt.length;i++) {
                saltHexString.append(Integer.toHexString(0xFF & salt[i]));
            }
            
            //Convert hashed salt+password bytes to hexadecimal
            StringBuffer saltedPasswordHexString = new StringBuffer();
            for (int i=0;i<hashedSaltedPassword.length;i++) {
                saltedPasswordHexString.append(Integer.toHexString(0xFF & hashedSaltedPassword[i]));
            }
            
            //Store both the username, salt, and hashed salt+password
            String storedUsername = inputUsername;
            String storedSalt = saltHexString.toString();
            String storedPassword = saltedPasswordHexString.toString();
            
            //Print Username and Hashed Salted Password
            System.out.print("\nYour Username is: " + storedUsername);
            System.out.print("\nYour salt is: " + storedSalt);
            System.out.print("\nYour hashed salted password is: " + storedPassword + "\n");
        
       } catch( NoSuchAlgorithmException | InvalidKeySpecException e ) {
            throw new RuntimeException( e );
       }
            
    }//END MAIN
}
