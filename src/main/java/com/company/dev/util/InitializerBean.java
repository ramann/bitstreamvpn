package com.company.dev.util;

import com.company.dev.model.app.domain.Payment;
import com.company.dev.model.app.repo.CertificateDao;
import com.company.dev.model.app.repo.PaymentDao;
import com.company.dev.model.app.repo.SubscriptionDao;
import com.company.dev.model.app.repo.UsersDao;
import com.company.dev.model.ipsec.domain.*;
import com.company.dev.model.ipsec.repo.*;
import com.google.common.util.concurrent.FutureCallback;
import com.google.common.util.concurrent.Futures;
import org.apache.commons.codec.digest.DigestUtils;
import org.bitcoinj.core.*;
import org.bitcoinj.kits.WalletAppKit;
import org.bitcoinj.params.RegTestParams;
import org.bitcoinj.wallet.Wallet;
import org.bitcoinj.wallet.listeners.WalletCoinsReceivedEventListener;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.pkcs.RSAPublicKey;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.RFC4519Style;
import org.bouncycastle.asn1.x509.Extension;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.*;
import org.springframework.stereotype.*;

import javax.security.auth.x500.X500Principal;
import javax.xml.bind.DatatypeConverter;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.math.BigDecimal;
import java.net.InetAddress;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.sql.Timestamp;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Date;

import static com.company.dev.util.Util.addDuration;
import static com.company.dev.util.Util.reverseSubject;


/**
 * This runs during startup.
 */
@Component
public class InitializerBean implements CommandLineRunner {

    @Value("${keystore.location}")
    public String keystoreLocation;

    public void run(String... args) {
        final Logger logger = LoggerFactory.getLogger(this.getClass());

        /**
         * Set up CA and Server cert in IPsec database
         */
        try {
            InputStream is = new FileInputStream(keystoreLocation);

            KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            keyStore.load(is, "changeit".toCharArray());
            String alias = "javaalias";

            X509Certificate caCert = (X509Certificate) keyStore.getCertificate("javaalias");

            /* Insert CA cert */
            Certificates caCertificates = new Certificates((byte) 1, (byte) 1, caCert.getEncoded());
            Certificates savedCaCertificates = (certificatesDao.findByData(caCert.getEncoded()) == null) ? certificatesDao.save(caCertificates) : null ;
            logger.debug("savedCaCertificate:"+savedCaCertificates);

            /* Insert CA Certificate Authority */
            CertificateAuthorities certificateAuthorities = new CertificateAuthorities(savedCaCertificates.getId());
            certificateAuthoritiesDao.save(certificateAuthorities);

            /* Insert CA identity (subject ASN.1 string) */

            //X500Name x500name = new X500Name(reverseSubject(caCert.getSubjectX500Principal().getName(X500Principal.RFC1779)));
            //ASN1Primitive asn1X500Name = ASN1Primitive.fromByteArray(x500name.getEncoded());
            ASN1Primitive asn1X500Name = ASN1Primitive.fromByteArray(caCert.getSubjectX500Principal().getEncoded());
            for (ASN1Encodable e : ASN1Sequence.getInstance(asn1X500Name)) {
                if(e instanceof ASN1Set) {
                    logger.debug("is set "+DatatypeConverter.printHexBinary(((ASN1Set) e).getEncoded()));
                    for (ASN1Encodable ee : ASN1Set.getInstance(e).toArray()) {
                        if(ee instanceof ASN1Sequence) {
                            logger.debug("is sequence:"+ DatatypeConverter.printHexBinary(((ASN1Sequence) ee).getEncoded()));
                            for (ASN1Encodable eee : ASN1Sequence.getInstance(ee).toArray()) {

                                if (eee instanceof DERUTF8String) {
                                    logger.debug("is utf8string " + DatatypeConverter.printHexBinary(((DERUTF8String) eee).getEncoded()));

                                } else if (eee instanceof DERPrintableString) {
                                    logger.debug("is printablestring " + DatatypeConverter.printHexBinary (((DERPrintableString) eee).getEncoded()));
                                }
                            }
                        }
                    }
                }
            }
            logger.debug("getName ca encoded: " + DatatypeConverter.printHexBinary(caCert.getSubjectX500Principal().getEncoded()));
            logger.debug(DatatypeConverter.printHexBinary(caCert.getEncoded()));
            Identities caSubjectIdentity = new Identities((byte) 9, caCert.getSubjectX500Principal().getEncoded());
            caSubjectIdentity.setCertificate(savedCaCertificates.getId());
            Identities savedCaSubjectIdentity = identitiesDao.save(caSubjectIdentity);

            /* Insert CA identity (pub key id) */
            Identities caPubKeyIdentity = new Identities((byte) 11, new DigestUtils().sha1(caCert.getPublicKey().getEncoded()));
            caPubKeyIdentity.setCertificate(savedCaCertificates.getId());
            Identities savedCaPubKeyIdentity = identitiesDao.save(caPubKeyIdentity);

            /* Insert CA identity (subject key id) */
            // TODO: do not use this - it only works if the oid is there in the cert. grab from the pub key
            byte[] caSubjKeyIdData = caCert.getExtensionValue(Extension.subjectKeyIdentifier.toString()); // gives us 041604142485D6C13EA7CF7F25F4A18AB5D4661EA0282A78
            logger.debug("bad length: "+caSubjKeyIdData.length);
            byte[] caSubjKeyIdDataTrimmed = Arrays.copyOfRange(caSubjKeyIdData,4,caSubjKeyIdData.length); // we want 2485D6C13EA7CF7F25F4A18AB5D4661EA0282A78
            logger.debug("good length: "+caSubjKeyIdDataTrimmed.length);
            Identities caSubjKeyIdentity = new Identities((byte) 11, caSubjKeyIdDataTrimmed);
            caSubjKeyIdentity.setCertificate(savedCaCertificates.getId());
            Identities savedCaSubjKeyIdentity = identitiesDao.save(caSubjKeyIdentity);

            /* Insert certificate identities for CA cert */
            logger.debug("saving cert-ident with ident "+savedCaSubjectIdentity.getId()+", data:"+
                    DatatypeConverter.printHexBinary(savedCaSubjectIdentity.getData()));
            certificateIdentityDao.save(new CertificateIdentity(savedCaCertificates.getId(), savedCaSubjectIdentity.getId()));

            logger.debug("saving cert-ident with ident "+savedCaPubKeyIdentity.getId()+", data:"+
                    DatatypeConverter.printHexBinary(savedCaPubKeyIdentity.getData()));
            certificateIdentityDao.save(new CertificateIdentity(savedCaCertificates.getId(), savedCaPubKeyIdentity.getId()));

            logger.debug("saving cert-ident with ident "+savedCaSubjKeyIdentity.getId()+", data:"+
                    DatatypeConverter.printHexBinary(savedCaSubjKeyIdentity.getData()));
            certificateIdentityDao.save(new CertificateIdentity(savedCaCertificates.getId(), savedCaSubjKeyIdentity.getId()));

            /* Insert pool and addresses */
            InetAddress startPoolAddress = InetAddress.getByName("10.11.12.13");
            InetAddress endPoolAddress = InetAddress.getByName("10.11.12.16");
            Pools pools = new Pools("bigpool", startPoolAddress.getAddress(), endPoolAddress.getAddress(), 0);
            poolsDao.save(pools);
            addressesDao.save(new Addresses(pools.getId(), InetAddress.getByName("10.11.12.13").getAddress()));
            addressesDao.save(new Addresses(pools.getId(), InetAddress.getByName("10.11.12.14").getAddress()));
            addressesDao.save(new Addresses(pools.getId(), InetAddress.getByName("10.11.12.15").getAddress()));
            addressesDao.save(new Addresses(pools.getId(), InetAddress.getByName("10.11.12.16").getAddress()));

            /* Insert server cert */
            X509Certificate serverCert = (X509Certificate) keyStore.getCertificate("javaserveralias");
            Certificates serverCertificates = new Certificates((byte) 1, (byte) 1, serverCert.getEncoded());
            Certificates savedServerCertificates = certificatesDao.save(serverCertificates);


            /* Insert Server identity (subject ASN.1 string) */
            //X500Name serverX500Name = new X500Name(reverseSubject(serverCert.getSubjectX500Principal().getName()));
            logger.debug("getName encoded: " + DatatypeConverter.printHexBinary(serverCert.getSubjectX500Principal().getEncoded()));
            logger.debug(DatatypeConverter.printHexBinary(serverCert.getEncoded()));
            Identities serverSubjectIdentity = new Identities((byte) 9, serverCert.getSubjectX500Principal().getEncoded());
            serverSubjectIdentity.setCertificate(savedServerCertificates.getId());
            Identities savedServerSubjectIdentity = identitiesDao.save(serverSubjectIdentity);

            /* Insert Server identity (pub key id) */
            Identities serverPubKeyIdentity = new Identities((byte) 11, new DigestUtils().sha1(serverCert.getPublicKey().getEncoded()));
            logger.debug("serverPubKeyIdentity: "+DatatypeConverter.printHexBinary(new DigestUtils().sha1(serverCert.getPublicKey().getEncoded())));
            serverPubKeyIdentity.setCertificate(savedServerCertificates.getId());
            Identities savedServerPubKeyIdentity = identitiesDao.save(serverPubKeyIdentity);
            logger.debug("reached");

            /*
             * Insert Server identity (subject key id)
             * Per ./src/libstrongswan/plugins/pkcs1/pkcs1_encoder.c, this is the ASN.1 sequence that wraps the
             * modulus and exponent of the public key
             */
            byte[] serverKeyIdentity = null;
            ByteArrayInputStream inStream = new ByteArrayInputStream(serverCert.getPublicKey().getEncoded());
            ASN1InputStream asnInputStream = new ASN1InputStream(inStream);
            ASN1Primitive pubKeyAsn1 = asnInputStream.readObject();
            for (ASN1Encodable a : ASN1Sequence.getInstance(pubKeyAsn1).toArray()) {
                if( a instanceof ASN1Sequence) { System.out.println("is sequence");}
                else { System.out.println("is not sequence"); }
                if (a instanceof ASN1BitString) {
                    System.out.println("is bitstring");
                    ASN1BitString b = (ASN1BitString) a;
                    serverKeyIdentity = new DigestUtils().sha1(b.getOctets());
                    System.out.println("sha1 of octets: "+DatatypeConverter.printHexBinary(serverKeyIdentity));
                }
                else { System.out.println("is not bitstring"); }
            }
            // do not use this - it only works if the oid is there in the cert. grab from the pub key
            /*byte[] subjKeyIdData = serverCert.getExtensionValue(Extension.subjectKeyIdentifier.toString());
            System.out.println("reached2");
            System.out.println("subjKeyIdData is null? "+(subjKeyIdData== null));
            System.out.println("bad length: "+subjKeyIdData.length);
            byte[] subjKeyIdDataTrimmed = Arrays.copyOfRange(subjKeyIdData,4,subjKeyIdData.length);
            System.out.println("good length: "+subjKeyIdDataTrimmed.length);*/
            Identities serverSubjKeyIdentity = new Identities((byte) 11, serverKeyIdentity);
            serverSubjKeyIdentity.setCertificate(savedServerCertificates.getId());
            Identities savedServerSubjKeyIdentity = identitiesDao.save(serverSubjKeyIdentity);

            /* Insert certificate identities for server cert */
            certificateIdentityDao.save(new CertificateIdentity(savedServerCertificates.getId(), savedServerSubjectIdentity.getId()));
            certificateIdentityDao.save(new CertificateIdentity(savedServerCertificates.getId(), savedServerPubKeyIdentity.getId()));
            certificateIdentityDao.save(new CertificateIdentity(savedServerCertificates.getId(), savedServerSubjKeyIdentity.getId()));

            /* Insert server private key */
            PrivateKey serverPrivateKey = (PrivateKey) keyStore.getKey("javaserveralias", "changeit".toCharArray());
            ByteArrayInputStream serverPrivKeyInStream = new ByteArrayInputStream(serverPrivateKey.getEncoded());
            ASN1InputStream serverPrivKeyAsn1InputStream = new ASN1InputStream(serverPrivKeyInStream);
            ASN1Primitive privKeyAsn1 = serverPrivKeyAsn1InputStream.readObject();
            byte[] serverPrivKeyOpensslForm = null;
            for (ASN1Encodable a : ASN1Sequence.getInstance(privKeyAsn1).toArray()) {
                if ( a instanceof ASN1OctetString) {
                    System.out.println("is ASN1OctetString");
                    ASN1OctetString o = (ASN1OctetString) a;
                    serverPrivKeyOpensslForm = o.getOctets();
                    System.out.println("serverPrivKeyOpensslForm: "+DatatypeConverter.printHexBinary(serverPrivKeyOpensslForm));
                }
                else {
                    System.out.println("isn't ASN1OctetString");
                }
            }

            PrivateKeys serverPrivateKeys = new PrivateKeys((byte) 1, serverPrivKeyOpensslForm);
            PrivateKeys savedServerPrivateKeys = privateKeysDao.save(serverPrivateKeys);

            PrivateKeyIdentity pkIdentServerSubject = new PrivateKeyIdentity(savedServerPrivateKeys.getId(), savedServerSubjectIdentity.getId());
            PrivateKeyIdentity pkIdentPubKey = new PrivateKeyIdentity(savedServerPrivateKeys.getId(), savedServerPubKeyIdentity.getId());
            PrivateKeyIdentity pkIdentSubjKey = new PrivateKeyIdentity(savedServerPrivateKeys.getId(), savedServerSubjKeyIdentity.getId());

            PrivateKeyIdentity savedPkIdentServerSubject =  privateKeyIdentityDao.save(pkIdentServerSubject);
            PrivateKeyIdentity savedPkIdentPubKey = privateKeyIdentityDao.save(pkIdentPubKey);
            PrivateKeyIdentity savedpkIdentSubjKey = privateKeyIdentityDao.save(pkIdentSubjKey);

        } catch (Exception e) {
            System.out.println(e.getMessage());
        }

    }


    @Autowired
    private CertificatesDao certificatesDao;

    @Autowired
    private IdentitiesDao identitiesDao;

    @Autowired
    private CertificateAuthoritiesDao certificateAuthoritiesDao;

    @Autowired
    private CertificateIdentityDao certificateIdentityDao;

    @Autowired
    private PoolsDao poolsDao;

    @Autowired
    private AddressesDao addressesDao;

    @Autowired
    private PrivateKeysDao privateKeysDao;

    @Autowired
    private PrivateKeyIdentityDao privateKeyIdentityDao;

}