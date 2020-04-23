package itis.semesterwork.infosec.protocols;

import itis.semesterwork.infosec.encryption.Sha1;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;

public class DiffieHellman {

    private final BigInteger p;
    private final BigInteger g;

    public DiffieHellman(int p, int g) {
        super();
        this.p = BigInteger.valueOf(p);
        this.g = BigInteger.valueOf(g);
    }

    public DiffieHellman(BigInteger p, BigInteger g) {
        super();
        this.p = p;
        this.g = g;
    }

    private BigInteger getPositiveBigInteger(BigInteger max) {
        SecureRandom realRandomGenerator = new SecureRandom();
        BigInteger result = new BigInteger(max.bitLength(), realRandomGenerator);
        return result.mod(max);
    }

    public KeyPair generateKeyPair() {
        BigInteger privateKey = getPositiveBigInteger(p);
        BigInteger publicKey = g.modPow(privateKey, p);

        return new KeyPair(privateKey, publicKey);
    }

    public byte[] sessionKeyWith(KeyPair aA, BigInteger otherPublicKey) {
        BigInteger s = otherPublicKey.modPow(aA.getPrivateKey(), p);
        return convertToKey(s);
    }

    public byte[] convertToKey(BigInteger s) {
        return Arrays.copyOf(Sha1.encode(s.toByteArray()), 16);
    }

    public BigInteger getP() {
        return p;
    }

    public BigInteger getG() {
        return g;
    }
}
