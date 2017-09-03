package com.company.dev.util;

import com.company.dev.model.app.domain.Purchase;
import com.company.dev.model.app.repo.PurchaseDao;
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
import org.bouncycastle.asn1.x509.Extension;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.*;
import org.springframework.stereotype.*;

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
import java.util.Date;

import static com.company.dev.util.Util.reverseSubject;

@Component
public class MyBean implements CommandLineRunner {
    public static WalletAppKit kit;

    @Autowired
    private UsersDao usersDao;

    @Autowired
    private PurchaseDao purchaseDao;

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

    public void run(String... args) {

        /**
         * Set up CA and Server cert in IPsec database
         */
        try {
            InputStream is = new FileInputStream("/home/ram/java/simple-webapp-spring-2/ipsec-pki/server.keystore");

            KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            keyStore.load(is, "changeit".toCharArray());
            String alias = "javaalias";

            X509Certificate caCert = (X509Certificate) keyStore.getCertificate("javaalias");

            /* Insert CA cert */
            Certificates caCertificates = new Certificates((byte) 1, (byte) 1, caCert.getEncoded());
            Certificates savedCaCertificates = certificatesDao.save(caCertificates);
            System.out.println("savedCaCertificate:"+savedCaCertificates);

            /* Insert CA Certificate Authority */
            CertificateAuthorities certificateAuthorities = new CertificateAuthorities(savedCaCertificates.getId());
            certificateAuthoritiesDao.save(certificateAuthorities);

            /* Insert CA identity (subject ASN.1 string) */
            X500Name x500name = new X500Name(reverseSubject(caCert.getSubjectX500Principal().getName()));
            System.out.println("getName encoded: " + DatatypeConverter.printHexBinary(x500name.getEncoded()));
            System.out.println(DatatypeConverter.printHexBinary(caCert.getEncoded()));
            Identities caSubjectIdentity = new Identities((byte) 9, x500name.getEncoded());
            Identities savedCaSubjectIdentity = identitiesDao.save(caSubjectIdentity);

            /* Insert CA identity (pub key id) */
            Identities caPubKeyIdentity = new Identities((byte) 11, new DigestUtils().sha1(caCert.getPublicKey().getEncoded()));
            Identities savedCaPubKeyIdentity = identitiesDao.save(caPubKeyIdentity);

            /* Insert CA identity (subject key id) */
            // TODO: do not use this - it only works if the oid is there in the cert. grab from the pub key
            byte[] caSubjKeyIdData = caCert.getExtensionValue(Extension.subjectKeyIdentifier.toString()); // gives us 041604142485D6C13EA7CF7F25F4A18AB5D4661EA0282A78
            System.out.println("bad length: "+caSubjKeyIdData.length);
            byte[] caSubjKeyIdDataTrimmed = Arrays.copyOfRange(caSubjKeyIdData,4,caSubjKeyIdData.length); // we want 2485D6C13EA7CF7F25F4A18AB5D4661EA0282A78
            System.out.println("good length: "+caSubjKeyIdDataTrimmed.length);
            Identities caSubjKeyIdentity = new Identities((byte) 11, caSubjKeyIdDataTrimmed);
            Identities savedCaSubjKeyIdentity = identitiesDao.save(caSubjKeyIdentity);

            /* Insert certificate identities for CA cert */
            System.out.println("saving cert-ident with ident "+savedCaSubjectIdentity.getId()+", data:"+
                    DatatypeConverter.printHexBinary(savedCaSubjectIdentity.getData()));
            certificateIdentityDao.save(new CertificateIdentity(savedCaCertificates.getId(), savedCaSubjectIdentity.getId()));

            System.out.println("saving cert-ident with ident "+savedCaPubKeyIdentity.getId()+", data:"+
                    DatatypeConverter.printHexBinary(savedCaPubKeyIdentity.getData()));
            certificateIdentityDao.save(new CertificateIdentity(savedCaCertificates.getId(), savedCaPubKeyIdentity.getId()));

            System.out.println("saving cert-ident with ident "+savedCaSubjKeyIdentity.getId()+", data:"+
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
            X500Name serverX500Name = new X500Name(reverseSubject(serverCert.getSubjectX500Principal().getName()));
            System.out.println("getName encoded: " + DatatypeConverter.printHexBinary(serverX500Name.getEncoded()));
            System.out.println(DatatypeConverter.printHexBinary(serverCert.getEncoded()));
            Identities serverSubjectIdentity = new Identities((byte) 9, serverX500Name.getEncoded());
            Identities savedServerSubjectIdentity = identitiesDao.save(serverSubjectIdentity);

            /* Insert Server identity (pub key id) */
            Identities serverPubKeyIdentity = new Identities((byte) 11, new DigestUtils().sha1(serverCert.getPublicKey().getEncoded()));
            System.out.println("serverPubKeyIdentity: "+DatatypeConverter.printHexBinary(new DigestUtils().sha1(serverCert.getPublicKey().getEncoded())));
            Identities savedServerPubKeyIdentity = identitiesDao.save(serverPubKeyIdentity);
System.out.println("reached");

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

        /**
         * Set up Bitcoin wallet
         */
        System.out.println("========= IS THIS THING ON =========");

        NetworkParameters params;
        String filePrefix;
        params = RegTestParams.get();

        filePrefix = "forwarding-service-regtest";
        Context context = new Context(params);
        // Start up a basic app using a class that automates some boilerplate.
        kit = new WalletAppKit(context, new File("."), filePrefix);

/*        if (params == RegTestParams.get()) {
            // Regression test mode is designed for testing and development only, so there's no public network for it.
            // If you pick this mode, you're expected to be running a local "bitcoind -regtest" instance.

        }*/
        kit.connectToLocalHost();

        // Download the block chain and wait until it's done.
        kit.startAsync();
        kit.awaitRunning();

        kit.wallet().addCoinsReceivedEventListener(new WalletCoinsReceivedEventListener() {
            @Override
            public void onCoinsReceived(Wallet w, Transaction tx, Coin prevBalance, Coin newBalance) {
                // Runs in the dedicated "user thread" (see bitcoinj docs for more info on this).
                //
                // The transaction "tx" can either be pending, or included into a block (we didn't see the broadcast).
                Coin value = tx.getValueSentToMe(w);
                System.out.println("Received tx for " + value.toFriendlyString() + ": " + tx);
                System.out.println("Transaction will be forwarded after it confirms.");
                //Users users = usersDao.findByUsername("mark"); //principal.getName()
                //Date d = new Date();

                //Purchase p = new Purchase(new Timestamp(d.getTime()), new BigDecimal(value.getValue()).movePointLeft(Coin.SMALLEST_UNIT_EXPONENT), kit.wallet().currentReceiveAddress().toString(), users);

                try {
                //    purchaseDao.save(p);
                } catch (Exception ex) {
                    System.out.println("Error creating the purchase: " + ex.toString());
                }


                // Wait until it's made it into the block chain (may run immediately if it's already there).
                //
                // For this dummy app of course, we could just forward the unconfirmed transaction. If it were
                // to be double spent, no harm done. Wallet.allowSpendingUnconfirmedTransactions() would have to
                // be called in onSetupCompleted() above. But we don't do that here to demonstrate the more common
                // case of waiting for a block.
                Futures.addCallback(tx.getConfidence().getDepthFuture(1), new FutureCallback<TransactionConfidence>() {
                    @Override
                    public void onSuccess(TransactionConfidence result) {
                        //forwardCoins(tx);
                        System.out.println("Some coins were received");

                        for(TransactionOutput t: tx.getOutputs()) {

                            System.out.println("output1: "+t.getAddressFromP2SH(params));
                            System.out.println("output2: "+t.getAddressFromP2PKHScript(params));

                            for (Purchase p:purchaseDao.findByReceivingAddress(t.getAddressFromP2PKHScript(params).toString())) {
                                p.setDateConfirm1(new Timestamp(new Date().getTime()));
                                p.setAmount(new BigDecimal(tx.getValueSentToMe(w).getValue()).movePointLeft(8));
                                purchaseDao.save(p);
                            }

                        }

                    //    p.setDateConfirm1(new Timestamp(new Date().getTime()));
                        try {
                    //        purchaseDao.save(p);
                        } catch (Exception ex) {
                            System.out.println("Error save confirmation 1: " + ex.toString());
                        }
                    }

                    @Override
                    public void onFailure(Throwable t) {
                        // This kind of future can't fail, just rethrow in case something weird happens.
                        throw new RuntimeException(t);
                    }
                });
            }
        });
    }


}