package algorithms;

public interface AsymmetricCipher {
	
	public String encrypt(String plainText);
	
	public String decrypt(String cipherText);
	
	public static void generateCertificates() {}
	
}
