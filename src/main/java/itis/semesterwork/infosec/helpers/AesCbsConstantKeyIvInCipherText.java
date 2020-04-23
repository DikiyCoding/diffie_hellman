package itis.semesterwork.infosec.helpers;

import itis.semesterwork.infosec.encryption.AesCbc;
import itis.semesterwork.infosec.utils.ArrayUtils;

import java.util.Arrays;

public class AesCbsConstantKeyIvInCipherText extends AesCbcConstantKey {

    private final ArrayUtils arrayUtils = new ArrayUtils();
    private final AesCbc aescbc = new AesCbc();

    public AesCbsConstantKeyIvInCipherText(byte[] key) {
        super(key);
    }

    public byte[] decrypt(byte[] ciphertext) {
        byte[] cleanCipherText = Arrays.copyOfRange(ciphertext, getBlockLength(), ciphertext.length);
        byte[] iv = Arrays.copyOfRange(ciphertext, 0, getBlockLength());
        return aescbc.decrypt(cleanCipherText, getKey(), iv);
    }

    public byte[] encrypt(byte[] plaintext) {
        byte[] iv = getIv();
        byte[] ciphertext = aescbc.encrypt(plaintext, getKey(), iv);
        return arrayUtils.join(iv, ciphertext);
    }

    public int getBlockLength() {
        return aescbc.getBlockSize();
    }
}
