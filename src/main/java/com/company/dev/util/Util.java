package com.company.dev.util;

import com.sun.deploy.util.StringUtils;
import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.crypto.generators.SCrypt;
import sun.misc.BASE64Encoder;
import sun.security.provider.X509Factory;

import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.text.SimpleDateFormat;
import java.util.*;

public class Util {

    public static String getHashedPassword(String password, String salt) {
        long startTime = System.nanoTime();
        byte hashedPassword[] = SCrypt.generate(password.getBytes(), Base64.decodeBase64(salt), 32768, 16, 4, 32);
        long endTime = System.nanoTime();

        long duration = (endTime - startTime);
        System.out.println("duration: "+duration);
        return Base64.encodeBase64String(hashedPassword);
    }

    public static String dateToGMT(Date date) {
        SimpleDateFormat sdf = new SimpleDateFormat();
        sdf.setTimeZone(new SimpleTimeZone(0, "GMT"));
        sdf.applyPattern("dd MMM yyyy HH:mm:ss z");

        return sdf.format(date);
    }

    public static String reverseSubject(String subject) {
        List subjectElements = Arrays.asList(subject.split(","));
        Collections.reverse(subjectElements);
        return StringUtils.join(subjectElements, ", ");
    }

    public static String prettyPrintCert(String uglyCert) {
        String certNice = "";
        BASE64Encoder encoder = new BASE64Encoder();
        certNice += X509Factory.BEGIN_CERT+"\n";

        for (String s:getParts(uglyCert,76)) {
            certNice += s+"\n";
        }

        certNice += X509Factory.END_CERT;
        //System.out.println("certNice: "+certNice);
        return certNice;
    }

    public static String prettyPrintCsr(String uglyCsr) {
        String certNice = "";
        BASE64Encoder encoder = new BASE64Encoder();
        certNice += "-----BEGIN CERTIFICATE REQUEST-----"+"\n";

        for (String s:getParts(uglyCsr,76)) {
            certNice += s+"\n";
        }

        certNice += "-----END CERTIFICATE REQUEST-----";
        //System.out.println("certNice: "+certNice);
        return certNice;
    }

    public static String prettyPrintCrl(String uglyCrl) {
        String crlNice = "";
        BASE64Encoder encoder = new BASE64Encoder();
        crlNice += "-----BEGIN X509 CRL-----"+"\n";

        for (String s:getParts(uglyCrl,76)) {
            crlNice += s+"\n";
        }

        crlNice += "-----END X509 CRL-----";
        //System.out.println("certNice: "+crlNice);
        return crlNice;
    }

    private static List<String> getParts(String string, int partitionSize) {
        List<String> parts = new ArrayList<String>();
        int len = string.length();
        for (int i=0; i<len; i+=partitionSize)
        {
            parts.add(string.substring(i, Math.min(len, i + partitionSize)));
        }
        return parts;
    }
}
