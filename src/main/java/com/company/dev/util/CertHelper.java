package com.company.dev.util;

import com.company.dev.model.app.domain.Certificate;
import com.company.dev.model.app.domain.Subscription;
import com.company.dev.model.app.domain.Users;
import com.company.dev.model.app.repo.CertificateDao;
import com.company.dev.model.ipsec.domain.*;
import com.company.dev.model.ipsec.repo.*;
import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.xml.bind.DatatypeConverter;
import java.io.IOException;
import java.io.StringReader;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.List;

import static com.company.dev.util.Util.*;

@Component
public class CertHelper {
    private final Logger logger = LoggerFactory.getLogger(this.getClass());

    public CertHelper() {};

    @Value("${keystore.location}")
    public String keystoreLocation;

    public X509Certificate certificateTox509Certificate(Certificate certificate) {
        Security.addProvider(new BouncyCastleProvider());
        X509Certificate x509Certificate = null;
        try {
            logger.debug("certificate.getCertText is null? "+ (certificate.getCertText() == null));
            PemReader pemReaderCert = new PemReader(new StringReader(prettyPrintCert(certificate.getCertText())));
            PemObject pemObjectCert = pemReaderCert.readPemObject();
            X509CertificateHolder x509CertificateHolder = new X509CertificateHolder(pemObjectCert.getContent());
            x509Certificate = new JcaX509CertificateConverter().setProvider("BC").getCertificate(x509CertificateHolder);
        } catch (IOException e) {
            logger.error("Error occurred getting X509Certificate from Certificate", e);
        } catch (CertificateException c) {
            logger.error("certificate exception", c);
        }

        return x509Certificate;
    }

    public boolean deleteIpsecRecordsForClient(X509Certificate x509Certificate) {
        logger.warn("entered deleteIpsecRecordsForClient");
        boolean ret = false;
        X500Name x500name = subjBytesToX500Name(x509Certificate.getSubjectX500Principal().getEncoded());
        try {
            Identities identitiesSubject = identitiesDao.findByData(x500name.getEncoded());
            Certificates certificates = certificatesDao.findByData(x509Certificate.getEncoded());
            logger.debug("identity id: "+identitiesSubject.getId());
            logger.debug("certificates id: "+certificates.getId());

/* todo: why doesn't this work?
             * certificateIdentityDao.findByCertificateAndIdentity(identitiesSubject.getId(), certificates.getId());
             */

            CertificateIdentity ci = certificateIdentityDao.findByCertificate(certificates.getId());
            logger.debug("ci: "+ci.getCertificate()+", "+ci.getIdentity());
            certificateIdentityDao.delete(ci);
            PeerConfigs peerConfigs = peerConfigsDao.findByRemoteId(Integer.toString(identitiesSubject.getId()));
            PeerConfigChildConfig peerConfigChildConfig = peerConfigChildConfigDao.findByPeerCfg(peerConfigs.getId());

            ChildConfigs childConfigs = childConfigsDao.findById(peerConfigChildConfig.getChildCfg());
            List<ChildConfigTrafficSelector> childConfigTrafficSelectors = childConfigTrafficSelectorDao.findByChildCfg(childConfigs.getId());

            for (ChildConfigTrafficSelector c : childConfigTrafficSelectors) {
                trafficSelectorsDao.delete(trafficSelectorsDao.findById(c.getTrafficSelector()));
                childConfigTrafficSelectorDao.delete(c);
            }
            childConfigsDao.delete(childConfigs);
            peerConfigChildConfigDao.delete(peerConfigChildConfig);
            ikeConfigsDao.delete(ikeConfigsDao.findById(peerConfigs.getIkeCfg()));
            peerConfigsDao.delete(peerConfigs);
            certificatesDao.delete(certificates);

            List<Addresses> addressesUsedByCert = addressesDao.findByIdentityIs(identitiesSubject.getId());
            for(Addresses a: addressesUsedByCert) {
                a.setIdentity(0);
                addressesDao.save(a);
            }

            identitiesDao.delete(identitiesSubject);

            ret = true;
        } catch (Exception e) {
            logger.error("didn't delete",e);
            ret = false;
        } finally {
            return ret;
        }
    }

    public boolean hasActiveConnection(String subject) {
        return (connectionsDao.findByPeerIdAndDisconnected(subject, false).size() > 0);
    }

    public Identities getIdentitiesForX509Certificate(X509Certificate x509Certificate) {
        Identities identities = null;
        try {
            X500Name x500name = subjBytesToX500Name(x509Certificate.getSubjectX500Principal().getEncoded());//new X500Name(reverseSubject(x509Certificate.getSubjectX500Principal().getName()));
            identities = new Identities((byte) 9, x500name.getEncoded());
        } catch (IOException e) {
            logger.error("unable to get encoded x500name", e);
        }
        return identities;
    }

    public void insertCertsIpsec(Subscription subscription) {
        List<Certificate> certs = certificateDao.findBySubscriptionAndSubscription_UsersOrderByDateCreated(subscription, subscription.getUsers());

        for (Certificate cert : certs) {
            try {
                X509Certificate x509Certificate = certificateTox509Certificate(cert);
                Identities tmpIdentities = getIdentitiesForX509Certificate(x509Certificate);
                if (identitiesDao.findByTypeAndData(tmpIdentities.getType(), tmpIdentities.getData()) == null) {
                    insertIpsecRecordsForClient(x509Certificate, keystoreLocation);
                }
            } catch (Exception e) {
                logger.error("failed to insert certificate: "+ cert.getSubject(), e);
            }
        }
    }

    public void removeCertsIpsec(Subscription subscription) {
        logger.info("entered removeCertsIpsec, sub: "+subscription.getId());
        List<Certificate> certs = certificateDao.findBySubscriptionAndSubscription_UsersOrderByDateCreated(subscription, subscription.getUsers());

        for (Certificate cert : certs) {
            try {
                X509Certificate x509Certificate = certificateTox509Certificate(cert);
                deleteIpsecRecordsForClient(x509Certificate);

                /*X500Name x500name = subjBytesToX500Name(x509Certificate.getSubjectX500Principal().getEncoded());//new X500Name(reverseSubject(x509Certificate.getSubjectX500Principal().getName()));
                logger.info("cert subj: " + DatatypeConverter.printHexBinary(x500name.getEncoded()) +
                        ", cert: " + DatatypeConverter.printHexBinary(x509Certificate.getEncoded()));*/
            } catch (Exception e) {
                logger.error("failed to remove certificate: "+ cert.getSubject(), e);
            }
        }
    }

    public void insertIpsecRecordsForClient(X509Certificate x509Certificate, String keystoreLocation) {
        logger.info("entered insertIpsecRecordsForClient");
        logger.info("is x509Certificate null? "+(x509Certificate == null));
        logger.info("keystoreLocation: "+keystoreLocation);

        try {
            logger.info("entered try block");
            // using X500Name
            X500Name x500name = subjBytesToX500Name(x509Certificate.getSubjectX500Principal().getEncoded());//new X500Name(reverseSubject(x509Certificate.getSubjectX500Principal().getName()));
            logger.info("cert subj: " + DatatypeConverter.printHexBinary(x500name.getEncoded())+
                    ", cert: "+ DatatypeConverter.printHexBinary(x509Certificate.getEncoded()));

            Identities identities = new Identities((byte) 9, x500name.getEncoded());
            Identities savedIdentities = identitiesDao.save(identities);
            logger.info("done with saved identites");
            logger.info("savedIdentities is null? "+(savedIdentities == null));

            Certificates certificates = new Certificates((byte) 1, (byte) 1, x509Certificate.getEncoded());
            certificates.setIdentity(savedIdentities.getId());
            Certificates savedCertificates = certificatesDao.save(certificates);
            logger.info("done with saved certificates");
            logger.info("savedCertificates is null? "+(savedCertificates == null));

            CertificateIdentity certificateIdentity = new CertificateIdentity(savedCertificates.getId(), savedIdentities.getId());
            CertificateIdentity savedCertificateIdentity = certificateIdentityDao.save(certificateIdentity);

            IkeConfigs ikeConfigs = new IkeConfigs(performNSLookup("strongswan"), "0.0.0.0"); // new IkeConfigs("104.236.219.189", "0.0.0.0");
            IkeConfigs savedIkeConfigs = ikeConfigsDao.save(ikeConfigs);

            X509Certificate serverCert = getServerCert(keystoreLocation);
            X500Name serverX500Name = subjBytesToX500Name(serverCert.getSubjectX500Principal().getEncoded());
/* new X500Name(reverseSubject(serverCert.getSubjectX500Principal().getName()));*/

            Identities savedServerSubjectIdentity = identitiesDao.findByData(serverX500Name.getEncoded());

            PeerConfigs peerConfigs = new PeerConfigs("rw",
                    savedIkeConfigs.getId(),
                    Integer.toString(savedServerSubjectIdentity.getId()),
                    Integer.toString(savedIdentities.getId()),
                    "bigpool");
            PeerConfigs savedPeerConfigs = peerConfigsDao.save(peerConfigs);

            ChildConfigs childConfigs = new ChildConfigs("rw", "/usr/local/bin/ipsec/_updown.sh"); // TODO: this script should be default
            ChildConfigs savedChildConfigs = childConfigsDao.save(childConfigs);

            PeerConfigChildConfig peerConfigChildConfig = new PeerConfigChildConfig(savedPeerConfigs.getId(), savedChildConfigs.getId());
            PeerConfigChildConfig savedPeerConfigChildConfig = peerConfigChildConfigDao.save(peerConfigChildConfig);

            byte[] startAddr = DatatypeConverter.parseHexBinary("00000000");
            byte[] endAddr = DatatypeConverter.parseHexBinary("ffffffff");
            TrafficSelectors trafficSelectorLocal = new TrafficSelectors((byte)7, startAddr, endAddr);
            TrafficSelectors savedTrafficSelectorLocal = trafficSelectorsDao.save(trafficSelectorLocal);

            TrafficSelectors trafficSelectorRemote = new TrafficSelectors((byte)7);
            TrafficSelectors savedTrafficSelectorRemote = trafficSelectorsDao.save(trafficSelectorRemote);

            ChildConfigTrafficSelector childConfigTrafficSelectorLocal = new ChildConfigTrafficSelector(savedChildConfigs.getId(),
                    savedTrafficSelectorLocal.getId(), (byte)0);
            ChildConfigTrafficSelector savedChildConfigTrafficSelectorLocal = childConfigTrafficSelectorDao.save(childConfigTrafficSelectorLocal);

            ChildConfigTrafficSelector childConfigTrafficSelectorRemote = new ChildConfigTrafficSelector(savedChildConfigs.getId(),
                    savedTrafficSelectorRemote.getId(), (byte)3);
            ChildConfigTrafficSelector savedChildConfigTrafficSelectorRemote = childConfigTrafficSelectorDao.save(childConfigTrafficSelectorRemote);

        } catch (Exception e) {
            logger.error("exception in insertIpsecRecordsForClient",e);
        }
    }

    @Autowired
    private CertificateDao certificateDao;

    @Autowired
    private CertificatesDao certificatesDao;

    @Autowired
    private CertificateIdentityDao certificateIdentityDao;

    @Autowired
    private IkeConfigsDao ikeConfigsDao;

    @Autowired
    private PeerConfigsDao peerConfigsDao;

    @Autowired
    private ChildConfigsDao childConfigsDao;

    @Autowired
    private PeerConfigChildConfigDao peerConfigChildConfigDao;

    @Autowired
    private TrafficSelectorsDao trafficSelectorsDao;

    @Autowired
    private ChildConfigTrafficSelectorDao childConfigTrafficSelectorDao;

    @Autowired
    private IdentitiesDao identitiesDao;

    @Autowired
    private AddressesDao addressesDao;

    @Autowired
    private ConnectionsDao connectionsDao;
}
