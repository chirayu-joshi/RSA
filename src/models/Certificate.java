package models;

import java.math.BigInteger;

public class Certificate {
	
	protected BigInteger exponent;
	protected BigInteger modulus;
	
	public BigInteger getExponent() {
		return exponent;
	}
	
	public BigInteger getModulus() {
		return modulus;
	}
	
}
