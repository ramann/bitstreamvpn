package com.company.dev.util;

import com.company.dev.model.ipsec.domain.*;
import com.company.dev.model.ipsec.repo.*;
import org.bouncycastle.asn1.x500.X500Name;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;

import javax.xml.bind.DatatypeConverter;
import java.security.cert.X509Certificate;
import java.util.List;

import static com.company.dev.util.Util.getServerCert;
import static com.company.dev.util.Util.subjBytesToX500Name;

public class IpsecCertUtil {
    private static final Logger logger = LoggerFactory.getLogger(IpsecCertUtil.class);

    public static String deleteIpsecRecordsForClient(X509Certificate x509Certificate) {
        logger.warn("entered deleteIpsecRecordsForClient");
        String ret = "starting";
        X500Name x500name = subjBytesToX500Name(x509Certificate.getSubjectX500Principal().getEncoded());
        try {
            Identities identitiesSubject = identitiesDao.findByData(x500name.getEncoded());
            Certificates certificates = certificatesDao.findByData(x509Certificate.getEncoded());
            logger.warn("identity id: "+identitiesSubject.getId());
            logger.warn("certificates id: "+certificates.getId());

/* todo: why doesn't this work?
             * certificateIdentityDao.findByCertificateAndIdentity(identitiesSubject.getId(), certificates.getId());
             */

            CertificateIdentity ci = certificateIdentityDao.findByCertificate(certificates.getId());
            logger.warn("ci: "+ci.getCertificate()+", "+ci.getIdentity());
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
            identitiesDao.delete(identitiesSubject);

            ret = "did work";
            return ret;
        } catch (Exception e) {
            logger.error("didn't delete",e);
        }
        return "we shouldn't have gotten here";
    }

    public static void insertIpsecRecordsForClient(X509Certificate x509Certificate, String keystoreLocation) {
        logger.debug("insertIpsecRecordsForClient");
        try {
            // using X500Name
            X500Name x500name = subjBytesToX500Name(x509Certificate.getSubjectX500Principal().getEncoded());//new X500Name(reverseSubject(x509Certificate.getSubjectX500Principal().getName()));
            logger.debug("cert subj: " + DatatypeConverter.printHexBinary(x500name.getEncoded())+
                    ", cert: "+ DatatypeConverter.printHexBinary(x509Certificate.getEncoded()));

            Identities identities = new Identities((byte) 9, x500name.getEncoded());
            Identities savedIdentities = identitiesDao.save(identities);

            Certificates certificates = new Certificates((byte) 1, (byte) 1, x509Certificate.getEncoded());
            Certificates savedCertificates = certificatesDao.save(certificates);

            CertificateIdentity certificateIdentity = new CertificateIdentity(savedCertificates.getId(), savedIdentities.getId());
            CertificateIdentity savedCertificateIdentity = certificateIdentityDao.save(certificateIdentity);

            IkeConfigs ikeConfigs = new IkeConfigs("174.138.46.113", "0.0.0.0");
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

            ChildConfigs childConfigs = new ChildConfigs("rw", "/usr/local/libexec/ipsec/_updown iptables"); // TODO: this script should be default
            ChildConfigs savedChildConfigs = childConfigsDao.save(childConfigs);

            PeerConfigChildConfig peerConfigChildConfig = new PeerConfigChildConfig(savedPeerConfigs.getId(), savedChildConfigs.getId());
            PeerConfigChildConfig savedPeerConfigChildConfig = peerConfigChildConfigDao.save(peerConfigChildConfig);

            TrafficSelectors trafficSelectorLocal = new TrafficSelectors((byte)7);
            TrafficSelectors savedTrafficSelectorLocal = trafficSelectorsDao.save(trafficSelectorLocal);

            TrafficSelectors trafficSelectorRemote = new TrafficSelectors((byte)7);
            TrafficSelectors savedTrafficSelectorRemote = trafficSelectorsDao.save(trafficSelectorRemote);

            ChildConfigTrafficSelector childConfigTrafficSelectorLocal = new ChildConfigTrafficSelector(savedChildConfigs.getId(),
                    savedTrafficSelectorLocal.getId(), (byte)2);
            ChildConfigTrafficSelector savedChildConfigTrafficSelectorLocal = childConfigTrafficSelectorDao.save(childConfigTrafficSelectorLocal);

            ChildConfigTrafficSelector childConfigTrafficSelectorRemote = new ChildConfigTrafficSelector(savedChildConfigs.getId(),
                    savedTrafficSelectorRemote.getId(), (byte)3);
            ChildConfigTrafficSelector savedChildConfigTrafficSelectorRemote = childConfigTrafficSelectorDao.save(childConfigTrafficSelectorRemote);

        } catch (Exception e) {
            logger.error("exception in insertIpsecRecordsForClient");
            logger.error(e.toString());
        }
    }



    @Autowired
    private static CertificatesDao certificatesDao;

    @Autowired
    private static CertificateIdentityDao certificateIdentityDao;

    @Autowired
    private static IkeConfigsDao ikeConfigsDao;

    @Autowired
    private static PeerConfigsDao peerConfigsDao;

    @Autowired
    private static ChildConfigsDao childConfigsDao;

    @Autowired
    private static PeerConfigChildConfigDao peerConfigChildConfigDao;

    @Autowired
    private static TrafficSelectorsDao trafficSelectorsDao;

    @Autowired
    private static ChildConfigTrafficSelectorDao childConfigTrafficSelectorDao;

    @Autowired
    private static IdentitiesDao identitiesDao;

}
