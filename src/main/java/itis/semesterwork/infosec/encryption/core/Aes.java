package itis.semesterwork.infosec.encryption.core;

import org.apache.shiro.crypto.AesCipherService;
import org.apache.shiro.crypto.OperationMode;
import org.apache.shiro.crypto.PaddingScheme;
import org.apache.shiro.util.ByteSource;

public class Aes implements CoreCipher {

    private final AesCipherService cipher;
    private final byte[] key;

    public Aes(byte[] key) {
        super();
        this.key = key;
        cipher = new AesCipherService();
        cipher.setMode(OperationMode.ECB);
        cipher.setPaddingScheme(PaddingScheme.NONE);
    }

    public byte[] encrypt(byte[] plaintext) {
        ByteSource ciphertext = cipher.encrypt(plaintext, key);
        return ciphertext.getBytes();
    }

    public byte[] decrypt(byte[] ciphertext) {
        ByteSource plaintext = cipher.decrypt(ciphertext, key);
        return plaintext.getBytes();
    }

    public int getBlockLength() {
        return key.length;
    }
}
