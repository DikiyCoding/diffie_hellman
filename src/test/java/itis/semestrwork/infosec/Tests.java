package itis.semestrwork.infosec;

import itis.semesterwork.infosec.main.challenges.n33.EchoBot;
import itis.semesterwork.infosec.main.challenges.n34.Dialog;
import itis.semesterwork.infosec.main.challenges.n35.MITMAttackG1;
import itis.semesterwork.infosec.main.challenges.n35.MITMAttackGP;
import itis.semesterwork.infosec.main.challenges.n35.MITMAttackGP1;
import itis.semesterwork.infosec.protocols.DiffieHellman;
import itis.semesterwork.infosec.protocols.KeyPair;
import itis.semesterwork.infosec.utils.ArrayUtils;
import org.junit.Test;

import java.math.BigInteger;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertTrue;

public class Tests {

    // Java gives negative result from the encoded number below
    private static final String pStrHex = "ffffffffffffffffc90fdaa22168c234" +
            "c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404" +
            "ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e" +
            "7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c" +
            "4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8" +
            "fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c35" +
            "4e4abc9804f1746c08ca237327ffffffffffffffff";

    // So here it is the decimal representation of that number as a string
    private static final String pStrDec = "24103124269210325885520760221975" +
            "66074856950548502459942654116941958108831682612228890093858261" +
            "34161467322714147790401219650364895705058263194273070680500922" +
            "30627347453410734066962460145893616597740410271692494532003787" +
            "29434170325843778659198143763193776859869524088940195577346119" +
            "84354530154704374720774996976375008430892633929555996888245787" +
            "24129938101291302945929999479263652640592846472097303849472116" +
            "81434464714438488520940127459844288859336526896320919633919";

    private static final BigInteger g = BigInteger.valueOf(2);
    private static final ArrayUtils arrayUtils = new ArrayUtils();

    @Test
    public void ex33ModSmall() {
        DiffieHellman diffieHellman = new DiffieHellman(37, 5);

        KeyPair aA = diffieHellman.generateKeyPair();
        KeyPair bB = diffieHellman.generateKeyPair();

        byte[] sBa = diffieHellman.sessionKeyWith(aA, bB.getPublicKey());
        byte[] sAb = diffieHellman.sessionKeyWith(bB, aA.getPublicKey());

        assertArrayEquals(sBa, sAb);
    }

    @Test
    public void ex33ModBig() {
        BigInteger p = new BigInteger(pStrDec);
        assertTrue(p.isProbablePrime(50));
        DiffieHellman diffieHellman = new DiffieHellman(p, g);

        KeyPair aA = diffieHellman.generateKeyPair();
        KeyPair bB = diffieHellman.generateKeyPair();

        byte[] sBa = diffieHellman.sessionKeyWith(aA, bB.getPublicKey());
        byte[] sAb = diffieHellman.sessionKeyWith(bB, aA.getPublicKey());

        assertArrayEquals(sBa, sAb);
    }

    @Test
    public void ex34MITMAttack() {
        EchoBot echo = new EchoBot();
        Dialog dialog = new Dialog(echo);

        byte[] message = arrayUtils.createInitializedArray(12, 12);
        byte[] response = dialog.talk(37, 5, message);

        assertArrayEquals(message, response);
    }

    @Test
    public void ex35MITMAttackG1() {
        EchoBot echo = new EchoBot();
        MITMAttackG1 attack = new MITMAttackG1(echo);
        Dialog A = new Dialog(attack);

        byte[] message = arrayUtils.createInitializedArray(12, 12);
        byte[] response = A.talk(37, 1, message);

        assertArrayEquals(message, response);
        assertArrayEquals(message, attack.getInterceptedMessage());
    }

    @Test
    public void ex35MITMAttackGP() {
        EchoBot echo = new EchoBot();
        MITMAttackGP attack = new MITMAttackGP(echo);
        Dialog A = new Dialog(attack);

        byte[] message = arrayUtils.createInitializedArray(12, 12);
        byte[] response = A.talk(37, 37, message);

        assertArrayEquals(message, response);
        assertArrayEquals(message, attack.getInterceptedMessage());
    }

    @Test
    public void ex35MITMAttackGP1() {
        EchoBot echo = new EchoBot();
        MITMAttackGP1 attack = new MITMAttackGP1(echo);
        Dialog A = new Dialog(attack);

        byte[] message = arrayUtils.createInitializedArray(12, 12);
        byte[] response = A.talk(37, 37 - 1, message);

        assertArrayEquals(message, response);
        assertArrayEquals(message, attack.getInterceptedMessage());
    }
}
