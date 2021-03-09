package models;

import java.io.IOException;

import java.nio.file.Files;
import java.nio.file.Paths;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class PublicCertificate extends Certificate {
		
	public PublicCertificate(String certificatePath) {
		try {
			
			byte[] publicKeyBytes = Files.readAllBytes(Paths.get(certificatePath));
			
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			PublicKey publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(publicKeyBytes));
			RSAPublicKeySpec rsaPublicKeySpec = keyFactory.getKeySpec(publicKey, RSAPublicKeySpec.class);
			
			super.exponent = rsaPublicKeySpec.getPublicExponent();
			super.modulus = rsaPublicKeySpec.getModulus();
			
		} catch (IOException e) {
			System.out.println("There was some problem while reading public certificate.");
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			System.out.println("There was some problem while applying RSA algorithm.");
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			e.printStackTrace();
		}
	}
	
}
