package itis.semesterwork.infosec.helpers;

import itis.semesterwork.infosec.encryption.AesCbc;
import itis.semesterwork.infosec.encryption.core.CoreCipher;
import org.apache.shiro.crypto.RandomNumberGenerator;
import org.apache.shiro.crypto.SecureRandomNumberGenerator;

public class AesCbcConstantKey implements EncryptingCipher, CoreCipher {

    private final byte[] key;
    private final byte[] iv;

    private final AesCbc aescbc = new AesCbc();

    public AesCbcConstantKey(byte[] key) {
        this.key = key;
        RandomNumberGenerator generator = new SecureRandomNumberGenerator();
        iv = generator.nextBytes(aescbc.getBlockSize()).getBytes();
    }

    public byte[] decrypt(byte[] ciphertext) {
        return aescbc.decrypt(ciphertext, key, iv);
    }

    public byte[] encrypt(byte[] plaintext) {
        return aescbc.encrypt(plaintext, key, iv);
    }

    public int getBlockLength() {
        return aescbc.getBlockSize();
    }

    protected byte[] getIv() {
        return iv;
    }

    protected byte[] getKey() {
        return key;
    }

    public int getBlockSize() {
        return aescbc.getBlockSize();
    }
}
