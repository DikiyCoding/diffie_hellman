package itis.semesterwork.infosec.encryption;

import itis.semesterwork.infosec.encryption.core.CoreCipher;
import itis.semesterwork.infosec.utils.ArrayUtils;

public class Cbc {

    private final ArrayUtils arrayUtils = new ArrayUtils();

    public byte[] encrypt(byte[] plaintext, byte[] iv, CoreCipher coreCipher) {
        byte[] result = new byte[plaintext.length];
        int blockLength = coreCipher.getBlockLength();
        int totalBlocks = arrayUtils.countBlocks(plaintext, blockLength);

        byte[] previousBlock = iv;
        for (int i = 0; i < totalBlocks; i++) {
            byte[] block = arrayUtils.extractBlock(plaintext, blockLength, i);
            byte[] blockToEncrypt = xor(previousBlock, block);

            previousBlock = coreCipher.encrypt(blockToEncrypt);
            arrayUtils.replaceBlock(result, previousBlock, i);
        }

        return result;
    }

    public byte[] decrypt(byte[] ciphertext, byte[] iv, CoreCipher coreCipher) {
        byte[] result = new byte[ciphertext.length];
        int blockLength = coreCipher.getBlockLength();
        int lastBlockIdx = arrayUtils.countBlocks(ciphertext, blockLength) - 1;

        byte[] currentCipherBlock = arrayUtils.extractBlock(ciphertext, blockLength, lastBlockIdx);
        for (int idx = lastBlockIdx; idx >= 0; idx--) {
            byte[] decrypt = coreCipher.decrypt(currentCipherBlock);
            byte[] previousCipherBlock = idx == 0 ? iv : arrayUtils.extractBlock(ciphertext, blockLength, idx - 1);
            byte[] plaintextBlock = xor(decrypt, previousCipherBlock);
            arrayUtils.replaceBlock(result, plaintextBlock, idx);
            currentCipherBlock = previousCipherBlock;
        }

        return result;
    }

    public byte[] xor(byte[] first, byte[] second) {
        byte[] shorter = first;
        byte[] longer = second;
        if (longer.length < shorter.length) {
            shorter = second;
            longer = first;
        }
        byte[] result = new byte[longer.length];
        for (int i = 0; i < longer.length; i++)
            result[i] = (byte) (longer[i] ^ shorter[i % shorter.length]);
        return result;
    }
}
