package itis.semesterwork.infosec.protocols;

import java.math.BigInteger;

public interface DiffieHellmanConversation {

    BigInteger initConversation(BigInteger p, BigInteger g, BigInteger publicKey);

    byte[] sendMessageExpectAnswer(byte[] message);
}