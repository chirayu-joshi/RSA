package algorithms;

import java.math.BigInteger;

import java.security.KeyPairGenerator;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.NoSuchAlgorithmException;

import java.io.IOException;
import java.io.FileOutputStream;

import models.PrivateCertificate;
import models.PublicCertificate;

public class RSA implements AsymmetricCipher {
	
	private final PublicCertificate myPublicCerti;
	private final PrivateCertificate myPrivateCerti;
	
	public RSA(PublicCertificate publicCerti, PrivateCertificate privateCerti) {
		myPublicCerti = publicCerti;
		myPrivateCerti = privateCerti;
	}
	
	// Encryption.
	/**
	 * This method receives plaintext as param and returns string of ciphertext.
	 * This method uses private key of user to encrypt the text so that receiver
	 * can decrypt cipher text with the public key of user.
	 * */
	@Override
	public String encrypt(String plainText) {
		// Returns p^e(modn)
		return (new BigInteger(plainText.getBytes()))
				.modPow(myPrivateCerti.getExponent(), myPrivateCerti.getModulus()).toString();
	}
	
	/**
	 * This method receives plaintext and returns cipher text generated using 
	 * publicCerti of receiver.  
	 * */
	public static String encrypt(String plainText, PublicCertificate publicCerti) {
		return (new BigInteger(plainText.getBytes()))
				.modPow(publicCerti.getExponent(), publicCerti.getModulus()).toString();
	}
	
	// Decryption.
	/**
	 * This method receives ciphertext as param and returns string of plaintext. 
	 * This method uses public key of receiver to decrypt the text which was initially
	 * encrypted using private key of receiver.
	 * */
	public static String decrypt(String cipherText, PublicCertificate publicCerti) {
		return new String((new BigInteger(cipherText))
				.modPow(publicCerti.getExponent(), publicCerti.getModulus()).toByteArray());
	}
	
	/**
	 * This method receives ciphertext which was encrypted by receiver using public key of user 
	 * and returns plaintext with the help of decryption using private key of user.
	 * */
	@Override
	public String decrypt(String cipherText) {
		return new String((new BigInteger(cipherText))
				.modPow(myPublicCerti.getExponent(), myPublicCerti.getModulus()).toByteArray());
	}
	
	/**
	 * This method receives ciphertext which was encrypted by public key of receiver.
	 * This method is specially used by trusted parties who has list of private certificates 
	 * of its users. 
	 * */
	public static String decrypt(String cipherText, PrivateCertificate privateCerti) {
		return new String((new BigInteger(cipherText))
				.modPow(privateCerti.getExponent(), privateCerti.getModulus()).toByteArray());
	}
	
	// Generate certificates for later use.
	/**
	 * This method generated public and private keys and stores them in 2 separate files.
	 * Those keys contains exponent (either e or d) and modulus (n)
	 * */
	public static void generateCertificates() {
		try {
			
			KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
			keyGen.initialize(2048);
			KeyPair keyPair = keyGen.genKeyPair();
			
			PrivateKey privateKey = keyPair.getPrivate();
			PublicKey publicKey = keyPair.getPublic();
			
			try {
				// Generate private key file.
				FileOutputStream fos = new FileOutputStream("./src/user/certificates/privateCertificate.pem");
				fos.write(privateKey.getEncoded());
				fos.close();
				
				// Generate public key file.
				fos = new FileOutputStream("./src/user/certificates/publicCertificate.pem");
				fos.write(publicKey.getEncoded());
				fos.close();
			} catch (IOException e) {
				e.printStackTrace();
			}
			
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
	}
	
}
