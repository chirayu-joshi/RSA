import algorithms.RSA;

import models.PrivateCertificate;
import models.PublicCertificate;

public class Main {
	
	public static void main(String[] args) {
		boolean shouldGenerateCertificate = false;
		
		if (shouldGenerateCertificate) {
			RSA.generateCertificates();
		}
		
		RSA myRSA = new RSA(new PublicCertificate("./src/user/certificates/publicCertificate.pem"), 
				new PrivateCertificate("./src/user/certificates/privateCertificate.pem"));
		
		String myMessage = "Hello! My name is Chirayu";
		System.out.println("Original Text: ");
		System.out.println(myMessage);
		System.out.println();
		
		String cipherText = myRSA.encrypt(myMessage);
		System.out.println("Before decryption: ");
		System.out.println(cipherText);
		System.out.println();
		
		String plainText = myRSA.decrypt(cipherText);
		System.out.println("After decryption: ");
		System.out.println(plainText);
		
		/* Below approach doesn't work because once myMessage is converted into myCipherText, it's length exceeds. So it has to be divided into chunks.
		// Encryption using my private key: 
		String myCipherText = myRSA.encrypt("Hello world! I am Chirayu..");
		System.out.println("myCipherText is: ");
		System.out.println(myCipherText);
		
		// Encrypting my cipher text (which can be decrypted only using my public key) into
		// cipher text using public key of my friend
		PublicCertificate friendPublicCerti = new PublicCertificate("./src/user/friend/publicCertificate.pem");
		String doubleCipher = RSA.encrypt(myCipherText, friendPublicCerti);
		System.out.println("doubleCipher is: ");
		System.out.println(doubleCipher);
		
		// Now friend receives double cipher. Only friend can decrypt double cipher because outer lock
		// is locked using public key of friend, so only private key of friend can unlock it.
		String innerLockedCipher = 
				RSA.decrypt(doubleCipher, new PrivateCertificate("./src/user/friend/privateCertificate.pem"));
		System.out.println("innerLockedCipher is: ");
		System.out.println(innerLockedCipher);
		System.out.println("Observe that innerLockedCipher is same as myCipherText");
		
		// Now friend removed first lock using his private key, and now he can decrypt inner lock using public key of mine.
		String originalMessage = myRSA.decrypt(innerLockedCipher);
		// You could also write:
		// String originalMessage = RSA.decrypt(innerLockedCipher, new PublicCertificate("./src/user/certificates/publicCertificate.pem"));
		System.out.println("Message received is: ");
		System.out.println(originalMessage);
		*/
	}
	
}