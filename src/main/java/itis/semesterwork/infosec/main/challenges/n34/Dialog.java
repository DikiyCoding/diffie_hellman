package itis.semesterwork.infosec.main.challenges.n34;

import itis.semesterwork.infosec.protocols.DiffieHellmanConversation;
import itis.semesterwork.infosec.helpers.AesCbcDynamicIVInCipherText;
import itis.semesterwork.infosec.protocols.KeyPair;
import itis.semesterwork.infosec.protocols.DiffieHellman;

import java.math.BigInteger;

public class Dialog {

    private final DiffieHellmanConversation friend;

    public Dialog(DiffieHellmanConversation friend) {
        this.friend = friend;
    }

    public byte[] talk(int p, int g, byte[] message) {
        DiffieHellman diffieHellman = new DiffieHellman(p, g);
        KeyPair aA = diffieHellman.generateKeyPair();
        BigInteger B = friend.initConversation(diffieHellman.getP(), diffieHellman.getG(), aA.getPublicKey());

        byte[] sessionKey = diffieHellman.sessionKeyWith(aA, B);
        AesCbcDynamicIVInCipherText cipher = new AesCbcDynamicIVInCipherText(sessionKey);

        byte[] answer = friend.sendMessageExpectAnswer(cipher.encrypt(message));
        return cipher.decrypt(answer);
    }
}
