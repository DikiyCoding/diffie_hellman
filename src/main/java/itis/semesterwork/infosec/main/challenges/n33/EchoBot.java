package itis.semesterwork.infosec.main.challenges.n33;

import itis.semesterwork.infosec.protocols.DiffieHellman;
import itis.semesterwork.infosec.protocols.DiffieHellmanConversation;
import itis.semesterwork.infosec.helpers.AesCbcDynamicIVInCipherText;
import itis.semesterwork.infosec.protocols.KeyPair;

import java.math.BigInteger;

public class EchoBot implements DiffieHellmanConversation {

    private AesCbcDynamicIVInCipherText cipher;

    public BigInteger initConversation(BigInteger p, BigInteger g, BigInteger publicKey) {
        DiffieHellman diffieHellman = new DiffieHellman(p, g);
        KeyPair keyPair = diffieHellman.generateKeyPair();
        byte[] sessionKey = diffieHellman.sessionKeyWith(keyPair, publicKey);
        cipher  = new AesCbcDynamicIVInCipherText(sessionKey);
        return keyPair.getPublicKey();
    }

    public byte[] sendMessageExpectAnswer(byte[] message) {
        byte[] plaintext = cipher.decrypt(message);
        return cipher.encrypt(plaintext);
    }
}
