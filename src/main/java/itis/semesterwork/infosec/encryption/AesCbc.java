package itis.semesterwork.infosec.encryption;

import itis.semesterwork.infosec.encryption.core.Aes;

import java.util.Arrays;

public class AesCbc {

    public byte[] decrypt(byte[] ciphertext, final byte[] key, byte[] iv) {
        Cbc cbc = new Cbc();
        byte[] paddedPlaintext = cbc.decrypt(ciphertext, iv, new Aes(key));
        byte paddingLength = paddedPlaintext[paddedPlaintext.length - 1];
        if (paddedPlaintext.length - paddingLength < 0) return paddedPlaintext;
        return Arrays.copyOf(paddedPlaintext, paddedPlaintext.length - paddingLength);
    }

    public byte[] encrypt(byte[] plaintext, final byte[] key, byte[] iv) {
        Cbc cbc = new Cbc();
        Aes coreCipher = new Aes(key);
        int fullBlocks = plaintext.length / coreCipher.getBlockLength();
        int paddedLength = (fullBlocks + 1) * coreCipher.getBlockLength();
        int padding = paddedLength - plaintext.length;
        byte[] paddedPlaintext = Arrays.copyOf(plaintext, paddedLength);
        Arrays.fill(paddedPlaintext, plaintext.length, paddedPlaintext.length, (byte) padding);
        return cbc.encrypt(paddedPlaintext, iv, coreCipher);
    }

    public int getBlockSize() {
        return 16;
    }
}
