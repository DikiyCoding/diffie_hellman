package itis.semesterwork.infosec.utils;

import java.util.Arrays;

public class ArrayUtils {

    public byte[] join(byte[] first, byte[]... rest) {
        byte[] result = first;
        for (byte[] next : rest)
            result = joinTwo(result, next);
        return result;
    }

    private byte[] joinTwo(byte[] first, byte[] second) {
        byte[] result = new byte[first.length + second.length];
        System.arraycopy(first, 0, result, 0, first.length);
        System.arraycopy(second, 0, result, first.length, second.length);
        return result;
    }

    public byte[] extractBlock(byte[] raw, int blockLength, int blockIndex) {
        int from = blockLength * (blockIndex);
        int to = Math.min(blockLength * (blockIndex + 1), raw.length);
        return Arrays.copyOfRange(raw, from, to);
    }

    public void replaceBlock(byte[] dest, byte[] block, int index) {
        System.arraycopy(block, 0, dest, block.length * (index), block.length);
    }

    public int countBlocks(byte[] raw, int blockLength) {
        int result = raw.length / blockLength;
        result += raw.length % blockLength == 0 ? 0 : 1;
        return result;
    }

    public byte[] intToBytes(int x) {
        byte[] bytes = new byte[4];
        for (int i = 0; x != 0; i++, x >>>= 8)
            bytes[4 - i - 1] = (byte) (x & 0xFF);
        return bytes;
    }

    public byte[] bitewiseToBytes(int[] ints) {
        byte[] result = new byte[0];
        for (int anInt : ints) result = join(result, intToBytes(anInt));
        return result;
    }

    public int[] bitewiseToIntegers(byte[] bytes) {
        int length = bytes.length / 4 + (bytes.length % 4 == 0 ? 0 : 1);
        int[] result = new int[length];
        for (int i = 0; i < bytes.length; i++) {
            int indx = i / 4;
            result[indx] = result[indx] << 8;
            result[indx] += bytes[i] & 0xff;
        }
        return result;
    }

    public byte[] createInitializedArray(int length, byte content) {
        byte[] result = new byte[length];
        Arrays.fill(result, content);
        return result;
    }

    public byte[] createInitializedArray(int length, int content) {
        return createInitializedArray(length, (byte) content);
    }
}
