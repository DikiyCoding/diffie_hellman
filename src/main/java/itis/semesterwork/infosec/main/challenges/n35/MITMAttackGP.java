package itis.semesterwork.infosec.main.challenges.n35;

import itis.semesterwork.infosec.protocols.DiffieHellman;
import itis.semesterwork.infosec.protocols.DiffieHellmanConversation;
import itis.semesterwork.infosec.helpers.AesCbcDynamicIVInCipherText;

import java.math.BigInteger;

public class MITMAttackGP implements DiffieHellmanConversation {

    private final DiffieHellmanConversation intendedFriendB;
    private byte[] interceptedMessage = null;
    private AesCbcDynamicIVInCipherText cipherB;

    public MITMAttackGP(DiffieHellmanConversation intendedFriend) {
        this.intendedFriendB = intendedFriend;
    }

    public BigInteger initConversation(BigInteger p, BigInteger g, BigInteger publicKey) {
        if (!p.equals(g)) throw new IllegalArgumentException("Attack works only for g = p");
        DiffieHellman diffieHellman = new DiffieHellman(1, 1);
        byte[] sessionKeyWithB = diffieHellman.convertToKey(BigInteger.valueOf(0));
        cipherB = new AesCbcDynamicIVInCipherText(sessionKeyWithB);
        return intendedFriendB.initConversation(p, g, publicKey);
    }

    public byte[] sendMessageExpectAnswer(byte[] message) {
        byte[] ciphertext = intendedFriendB.sendMessageExpectAnswer(message);
        interceptedMessage = decrypt(ciphertext);
        return ciphertext;
    }

    public byte[] getInterceptedMessage() {
        return interceptedMessage;
    }

    private byte[] decrypt(byte[] ciphertext) {
        return cipherB.decrypt(ciphertext);
    }
}
