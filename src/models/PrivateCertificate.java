package models;

import java.io.IOException;

import java.nio.file.Files;
import java.nio.file.Paths;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateKeySpec;

public class PrivateCertificate extends Certificate {
	
	public PrivateCertificate(String certificatePath) {
		try {
			
			byte[] privateKeyBytes = Files.readAllBytes(Paths.get(certificatePath));
			
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			PrivateKey privateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(privateKeyBytes));
			RSAPrivateKeySpec rsaPrivateKeySpec = keyFactory.getKeySpec(privateKey, RSAPrivateKeySpec.class);
			
			super.exponent = rsaPrivateKeySpec.getPrivateExponent();
			super.modulus = rsaPrivateKeySpec.getModulus();
			
		} catch (IOException e) {
			System.out.println("There was some problem while reading private certificate.");
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			System.out.println("There was some problem while applying RSA algorithm.");
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			e.printStackTrace();
		}
	}

}
