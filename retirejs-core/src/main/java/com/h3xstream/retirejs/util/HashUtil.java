package com.h3xstream.retirejs.util;

import java.security.DigestException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class HashUtil {

    public void hashSha1(byte[] content, int offset) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-1");
            digest.digest(content, offset, content.length - offset);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e); //Will never happen, unless executed on a martian JVM.
        } catch (DigestException e) {
            throw new RuntimeException(e); //Will never happen, unless executed on a martian JVM.
        }
    }
}
