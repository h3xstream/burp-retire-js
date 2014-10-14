package com.h3xstream.retirejs.util;

import java.security.DigestException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class HashUtil {

    public static String hashSha1(byte[] content, int offset) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-1");
            digest.update(content, offset, content.length - offset);
            return toHex(digest.digest());
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e); //Will never happen, unless executed on a martian JVM.
        }
    }

    private static String toHex(byte[] value) {
        StringBuilder sb = new StringBuilder();
        for (byte b : value) {
            sb.append(String.format("%02X", b));
        }
        return sb.toString();
    }
}
