package com.company.dev.util;

import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.crypto.generators.SCrypt;

public class Util {

    public static String getHashedPassword(String password, String salt) {
        long startTime = System.nanoTime();
        byte hashedPassword[] = SCrypt.generate(password.getBytes(), Base64.decodeBase64(salt), 32768, 16, 4, 32);
        long endTime = System.nanoTime();

        long duration = (endTime - startTime);
        System.out.println("duration: "+duration);
        return Base64.encodeBase64String(hashedPassword);
    }
}
