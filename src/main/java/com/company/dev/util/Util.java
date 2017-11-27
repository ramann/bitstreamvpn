package com.company.dev.util;

import com.company.dev.model.app.domain.Certificate;
import com.company.dev.model.app.domain.Payment;
import com.company.dev.model.app.domain.Subscription;
import com.company.dev.model.ipsec.domain.Identities;
import com.company.dev.model.ipsec.repo.IdentitiesDao;
//import com.sun.deploy.util.StringUtils;
import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509ExtensionUtils;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.crypto.generators.SCrypt;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;
import org.bouncycastle.operator.bc.BcRSAContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.client.ClientHttpRequestFactory;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.thymeleaf.util.StringUtils;

import javax.xml.bind.DatatypeConverter;
import java.io.FileInputStream;
import java.io.InputStream;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.math.RoundingMode;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.sql.Timestamp;
import java.text.SimpleDateFormat;
import java.util.*;

public class Util {
    private static final Logger logger = LoggerFactory.getLogger(Util.class);
    public static final String BEGIN_CERT = "-----BEGIN CERTIFICATE-----";
    public static final String END_CERT = "-----END CERTIFICATE-----";
//    public static int[] durations = {72, 168, 720};

    // let's say 0.02 USD/hour
//    public static final double pricePerUnit = 0.02;

    public static String performNSLookup(String name) {
        InetAddress inetHost = null;
        String ret;
        try {
            inetHost = InetAddress.getByName(name);
            String hostName = inetHost.getHostName();
            logger.info("The host name was: " + hostName);
            logger.info("The hosts IP address is: " + inetHost.getHostAddress());
            ret = inetHost.getHostAddress();
        } catch(UnknownHostException ex) {
            logger.error("Unrecognized host",ex);
            ret = "104.236.219.189"; //"172.18.0.5"; //TODO: fix this logic
        }
        return ret;
    }

    public static BigDecimal bytesToGigabytes(BigInteger bytes) {
        BigDecimal gigabytes = new BigDecimal(bytes).divide(new BigDecimal("1000").pow(3)).setScale(2, RoundingMode.HALF_UP);
        return gigabytes;
    }

    public static String errorText(String objectName, String objectValue) {
        objectName = objectName.substring(objectName.lastIndexOf('.') + 1).trim();
        return "Could not find "+objectName+" " +objectValue+ ".";
    }

    public static String errorText(String objectName, String objectValue, String userName) {
        objectName = objectName.substring(objectName.lastIndexOf('.') + 1).trim();
        return "Could not find "+objectName+" "+objectValue+" for user: "+userName;
    }

    public static Timestamp addDuration(Timestamp timestamp, int duration, int calendarUnit) {
        Calendar cal = Calendar.getInstance();
        cal.setTime(timestamp);
        cal.add(calendarUnit, duration);
        return new Timestamp(cal.getTimeInMillis());
    }


    public static byte[] getHashedPassword(String password, byte[] salt) {
        long startTime = System.nanoTime();
        byte hashedPassword[] = SCrypt.generate(password.getBytes(), salt, 32768, 16, 4, 32);
        long endTime = System.nanoTime();

        long duration = (endTime - startTime);
        System.out.println("duration: "+duration);
        return hashedPassword;
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

    public static String printBasicCertInfo(X509CertificateHolder cert) {
        return "serial: "+cert.getSerialNumber()+"\n"+
                "subject: "+ cert.getSubject().toString()+"\n"+
                "creation date: "+dateToGMT(cert.getNotBefore())+"\n"+
                "expiration date: "+dateToGMT(cert.getNotAfter()); // TODO display time in GMT
    }

    public static String prettyPrintCert(String uglyCert) {
        String certNice = "";
        certNice += BEGIN_CERT+"\n";

        for (String s:getParts(uglyCert,64)) {
            certNice += s+"\n";
        }

        certNice += END_CERT;
        //System.out.println("certNice: "+certNice);
        return certNice;
    }

    public static String prettyPrintCsr(String uglyCsr) {
        String certNice = "";
        certNice += "-----BEGIN CERTIFICATE REQUEST-----"+"\n";

        for (String s:getParts(uglyCsr,64)) {
            certNice += s+"\n";
        }

        certNice += "-----END CERTIFICATE REQUEST-----";
        //System.out.println("certNice: "+certNice);
        return certNice;
    }

    public static String prettyPrintCrl(String uglyCrl) {
        String crlNice = "";
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

    public static X509Certificate getServerCert(String keystoreLocation) {
        X509Certificate serverCert = null;
        try {
            InputStream is = new FileInputStream(keystoreLocation);

            KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            keyStore.load(is, "changeit".toCharArray());
            serverCert = (X509Certificate) keyStore.getCertificate("javaserveralias");

        } catch (Exception e) {
            System.out.println(e);
        }
        return serverCert;
    }

    /* take a Subject and convert it to use PRINTABLESTRINGs and return the X500Name */
    public static X500Name subjBytesToX500Name(byte[] subjBytes) {
        logger.info("entered subjBytesToX500Name with data: "+DatatypeConverter.printHexBinary(subjBytes));

        ArrayList<RDN> rdns = new ArrayList<RDN>();

        try {
            ASN1Primitive caSubj = ASN1Primitive.fromByteArray(subjBytes);

            if (caSubj instanceof ASN1Sequence) {
                logger.debug("caSubj is ASN1Sequence!!!");
                //org.bouncycastle.asn1.DLSequence;
                ASN1Sequence a = (DLSequence) caSubj;
                logger.debug("a: " + a.size());
                //ASN1ObjectIdentifier b = new ASN1ObjectIdentifier("2.5.4.6");
                //ASN1Encodable[] e = a.toArray();

                for (ASN1Encodable ee : a.toArray()) {
                    ASN1ObjectIdentifier oid = null;
                    ASN1Encodable ae = null;
                    logger.debug("looping through sequence");
                    if (ee instanceof ASN1Set) {
                        ASN1Set set = (ASN1Set) ee;
                        for (ASN1Encodable eee : set.toArray()) {
                            logger.debug("looping through set");
                            if (eee instanceof ASN1Sequence) {

                                for (ASN1Encodable eeee : ((ASN1Sequence) eee).toArray()) {
                                    logger.debug("looping through inner sequence");
                                    logger.debug(eeee.getClass().toString());
                                    if (eeee instanceof ASN1ObjectIdentifier) {
                                        logger.debug("oid: ");
                                        ASN1ObjectIdentifier x = (ASN1ObjectIdentifier) eeee;
                                        logger.debug(" id: " + x.getId());
                                        oid = x;
                                    }

                                    if (eeee instanceof DERPrintableString) {
                                        DERPrintableString xx = (DERPrintableString) eeee;
                                        logger.debug(" printablestring: " + xx.getString());
                                        ae = eeee;
                                    }

                                    if (eeee instanceof DERUTF8String) {
                                        DERUTF8String xx = (DERUTF8String) eeee;
                                        logger.debug("utf8string: "+xx.getString());
                                        ae = new DERPrintableString(xx.getString());
                                    }
                                }
                            }
                        }
                    }
                    RDN r = new RDN(oid, ae);
                    logger.debug("r: "+DatatypeConverter.printHexBinary(r.getEncoded()));
                    rdns.add(r);
                    logger.debug("rdns: "+rdns.size());
                }
            }
            return new X500Name(rdns.toArray(new RDN[0]));
        } catch (Exception e) {
            logger.error("Couldn't parse subjBytes", e);
        }
        logger.info("leaving subjBytesToX500Name");
        return null;
    }

    public static X509CertificateHolder signCert(byte[] subj, byte[] csr, KeyStore keyStore, PrivateKey caKey) {
        X509CertificateHolder holder = null;
        try {
            PKCS10CertificationRequest pkcs10CertificationRequest = new PKCS10CertificationRequest(csr);


            BigInteger serial = new BigInteger(32, new SecureRandom());

            X500Name issuer = subjBytesToX500Name(subj /*caCert.getSubjectX500Principal().getEncoded()*/);

            Date from = new Date();
            Date to = new Date(System.currentTimeMillis() + (30 * 86400000L));

            X509v3CertificateBuilder certgen = new X509v3CertificateBuilder(issuer, serial, from, to,
                    subjBytesToX500Name(pkcs10CertificationRequest.getSubject().getEncoded()),
                    pkcs10CertificationRequest.getSubjectPublicKeyInfo());


    /*        certgen.addExtension( Extension.basicConstraints, false, new BasicConstraints( false ) );
            certgen.addExtension(Extension.keyUsage, true, new KeyUsage( KeyUsage.digitalSignature | KeyUsage.keyEncipherment));
            KeyPurposeId[] usages = {KeyPurposeId.id_kp_emailProtection, KeyPurposeId.id_kp_clientAuth};
            certgen.addExtension(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(usages));
            certgen.addExtension(Extension.subjectKeyIdentifier, false, new SubjectKeyIdentifier(new DigestUtils().sha1(pkcs10CertificationRequest.getSubjectPublicKeyInfo().parsePublicKey().getEncoded())));
    */

            X509CertificateHolder caCertHolder = new X509CertificateHolder(keyStore.getCertificate("javaalias").getEncoded());
            DigestCalculator dc = new BcDigestCalculatorProvider().get(new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1));
            AuthorityKeyIdentifier aki = new X509ExtensionUtils(dc).createAuthorityKeyIdentifier(caCertHolder.getSubjectPublicKeyInfo());
            certgen.addExtension(Extension.authorityKeyIdentifier, false, aki);

            AlgorithmIdentifier sigAlgId = new DefaultSignatureAlgorithmIdentifierFinder().find("SHA256withRSA");
            AlgorithmIdentifier digAlgId = new DefaultDigestAlgorithmIdentifierFinder().find(sigAlgId);
            ContentSigner signer = new BcRSAContentSignerBuilder(sigAlgId, digAlgId).build(PrivateKeyFactory.createKey(caKey.getEncoded()));
             holder = certgen.build(signer);
        } catch (Exception e) {

        }
        return holder;
    }

    public static PrivateKey getPrivateKey(String keystoreLocation) {
        PrivateKey caKey = null;
        try {
            InputStream is = new FileInputStream(keystoreLocation);

            KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            keyStore.load(is, "changeit".toCharArray());
            String alias = "javaalias";

            caKey = (PrivateKey) keyStore.getKey(alias, "changeit".toCharArray());
        } catch (Exception e) {

        }
        return caKey;
    }

    public static void hashPass(String password) {
        SecureRandom random = new SecureRandom();
        byte slt[] = new byte[8];
        random.nextBytes(slt);
        Util.getHashedPassword(password, slt);
    }
}
