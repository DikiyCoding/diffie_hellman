package itis.semesterwork.infosec.helpers;

import org.apache.shiro.crypto.RandomNumberGenerator;
import org.apache.shiro.crypto.SecureRandomNumberGenerator;

public class AesCbcDynamicIVInCipherText extends AesCbsConstantKeyIvInCipherText {

    public AesCbcDynamicIVInCipherText(byte[] sessionKey) {
        super(sessionKey);
    }

    @Override
    protected byte[] getIv() {
        RandomNumberGenerator generator = new SecureRandomNumberGenerator();
        return generator.nextBytes(getBlockSize()).getBytes();
    }
}
