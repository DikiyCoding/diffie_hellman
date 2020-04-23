package itis.semesterwork.infosec.encryption.core;

public interface CoreCipher {

    byte[] encrypt(byte[] plaintext);

    byte[] decrypt(byte[] ciphertext);

    int getBlockLength();
}
