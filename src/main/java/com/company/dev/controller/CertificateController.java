package com.company.dev.controller;

import com.company.dev.model.app.domain.Certificate;
import com.company.dev.model.app.domain.Users;
import com.company.dev.model.app.repo.CertificateDao;
import com.company.dev.model.app.repo.SubscriptionDao;
import com.company.dev.model.app.repo.UsersDao;
import com.company.dev.model.ipsec.domain.*;
import com.company.dev.model.ipsec.repo.*;
import com.company.dev.util.Util;
import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;

import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import javax.xml.bind.DatatypeConverter;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.StringReader;
import java.math.BigInteger;
import java.nio.charset.Charset;
import java.security.*;
import java.security.cert.X509Certificate;
import java.sql.Timestamp;
import java.util.Date;
import java.util.List;

import static com.company.dev.util.Util.*;
import static com.company.dev.util.Util.dateToGMT;
import static java.lang.System.out;

@Controller
public class CertificateController {
    private final Logger logger = LoggerFactory.getLogger(this.getClass());

    @RequestMapping(method= RequestMethod.POST, value="/deleteCert")
    public String postDeleteCert(Model model, Principal principal, String serial, String password, HttpSession session) {
        Security.addProvider(new BouncyCastleProvider());

        if(usersDao.findByUsername(principal.getName()) != null) {
            logger.debug("password: "+password);
            Users user = usersDao.findByUsername(principal.getName());
            String hashedPassword = Util.getHashedPassword(password, user.getSalt());

            if ( !hashedPassword.equals(user.getPassword())) {
                logger.warn("invalid password when trying to delete cert");
                session.setAttribute("invalidPassword",true);
                //model.addAttribute("invalidPassword",true);
                return "redirect:/deleteCert?serial="+serial;
            } else {
                logger.debug("password was good");
            }
        } else {
            hashPass(password);
            System.out.println("User not found");
            return null;
        }

        try {
            Certificate cert = certificateDao.findBySerial(Long.valueOf(serial));
            PemReader pemReaderCert = new PemReader(new StringReader(prettyPrintCert(cert.getCertText())));
            PemObject pemObjectCert = pemReaderCert.readPemObject();
            X509CertificateHolder x509CertificateHolder = new X509CertificateHolder(pemObjectCert.getContent());
            X509Certificate x509Certificate =  new JcaX509CertificateConverter().setProvider( "BC" ).getCertificate( x509CertificateHolder );
            logger.info("did we delete? "+deleteIpsecRecordsForClient(x509Certificate));
            certificateDao.delete(cert);
            System.out.println("we've deleted...");
            //System.out.println(prettyPrintCrl(Base64.encodeBase64String(x509CRLHolder.getEncoded())));
            model.addAttribute("revoked", "cert "+serial+" has been deleted.");
        } catch (Exception e) {
            System.out.println("something bad happened in crl");
            System.out.println(e);
            return "error deleting cert";
        }
        session.setAttribute("certDeleted",true);
        return "redirect:/myaccount";
    }

    @RequestMapping(method=RequestMethod.GET, value="/deleteCert")
    public String deleteCert(Model model, Principal principal, String serial, HttpSession session){
        Certificate certificate = certificateDao.findBySerial(Long.valueOf(serial));
        X509CertificateHolder cert = null;
        try {
            PemReader pemReaderCert = new PemReader(new StringReader(prettyPrintCert(certificate.getCertText())));
            PemObject pemObjectCert = pemReaderCert.readPemObject();
            cert = new X509CertificateHolder(pemObjectCert.getContent());
        } catch (Exception e) {
            logger.error("exception "+e);
        }
        model.addAttribute("invalidPassword", (session.getAttribute("invalidPassword")));
        model.addAttribute("username", principal.getName());
        model.addAttribute("certInfo", printBasicCertInfo(cert));
        model.addAttribute("certificate", certificate);
        session.removeAttribute("invalidPassword");
        return "deleteCert";
    }


    @RequestMapping(method=RequestMethod.GET, value="/downloadCert")
    @ResponseBody
    public void downloadCert(Principal principal, long serial, HttpServletResponse response) {
        Certificate certificate = certificateDao.findBySerial(serial);

        response.setContentType("text/plain");
        String prettyCert = prettyPrintCert(certificate.getCertText());
        try {
            response.getOutputStream().write(prettyCert.getBytes(Charset.forName("UTF-8")));
            response.flushBuffer();
        } catch (IOException e) {
            logger.error("failed to getOutputStream when downloading cert (serial:"+serial+")");
        }
        return;
    }

    @RequestMapping(method=RequestMethod.GET, value="/certs")
    public String csr(Model model, Principal principal, int subscriptionId) {

        List<Certificate> certificates = certificateDao.findBySubscription(subscriptionDao.findById(subscriptionId));

        for(Certificate c:certificates) {
            try {
                PemReader pemReaderCsr = new PemReader(new StringReader(prettyPrintCsr(c.getCsrText())));
                PemObject pemObjectCsr = pemReaderCsr.readPemObject();
                PKCS10CertificationRequest pkcs10CertificationRequest = new PKCS10CertificationRequest(pemObjectCsr.getContent());
                System.out.println("cert req: "+pkcs10CertificationRequest.getSubject());
                c.setCsrText(pkcs10CertificationRequest.getSubject().toString());

                PemReader pemReaderCert = new PemReader(new StringReader(prettyPrintCert(c.getCertText())));
                PemObject pemObjectCert = pemReaderCert.readPemObject();
                X509CertificateHolder cert = new X509CertificateHolder(pemObjectCert.getContent());
                c.setCertText("serial: "+cert.getSerialNumber()+"\n"+
                        "subject: "+ cert.getSubject().toString()+"\n"+
                        "expires on "+dateToGMT(cert.getNotAfter())); // TODO display time in GMT
                System.out.println("c:"+c.getCertText());
            } catch (Exception e) {
                logger.error("Error reading pem of CSR or cert");
                logger.error(e.toString());
            }
        }

        model.addAttribute("subscriptionId", subscriptionId);
        model.addAttribute("certificates", certificates);
        model.addAttribute("certificatesSize", certificates.size());
        model.addAttribute("username", principal.getName());
        return "certs";
    }

    @RequestMapping(method=RequestMethod.GET, value="/addCert")
    public String addCert(Model model, Principal principal, HttpSession session, int subscriptionId) {
        model.addAttribute("subscriptionId", subscriptionId);
        model.addAttribute("username", principal.getName());
        return "addCert";
    }

    // TODO java uses UTF8STRING but openssl uses PRINTABLESTRING ...
    // TODO scripts/id2sql "C=US, O=test, CN=peer2" also uses PRINTABLESTRING so be mindful comparing its output with Java
    // TODO should we use PRINTABLESTRING
    @RequestMapping(method=RequestMethod.POST, value="/addCert")
    public String postCSR(Model model, Principal principal, String csr, HttpSession session, int subscriptionId) {
        model.addAttribute("username", principal.getName());
        logger.info("das CSR: "+csr);
        logger.info("username: "+principal.getName());
        FileInputStream is;
        Certificate savedCert = null;
        try {
            Security.addProvider(new BouncyCastleProvider());
            logger.debug("found payment!");
            is = new FileInputStream("/home/ram/java/simple-webapp-spring-2/ipsec-pki/server.keystore");
            KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            keyStore.load(is, "changeit".toCharArray());

            PemReader pemReaderCsr = new PemReader(new StringReader(csr));
            PemObject pemObjectCsr = pemReaderCsr.readPemObject();
            logger.info("the CSR: "+ Base64.encodeBase64String(pemObjectCsr.getContent()));

            BigInteger serial = new BigInteger( 32, new SecureRandom() );
            Certificate certificate = new Certificate(new Timestamp(new Date().getTime()),
                    Base64.encodeBase64String(pemObjectCsr.getContent()), false,
                    subscriptionDao.findById(subscriptionId), serial.longValue());
            Certificate Certificate = certificateDao.save(certificate);

            X509Certificate caCert = (X509Certificate) keyStore.getCertificate("javaalias");
            PrivateKey caKey = (PrivateKey) keyStore.getKey("javaalias", "changeit".toCharArray());
            logger.info("CA subject:"+ subjBytesToX500Name(caCert.getSubjectX500Principal().getEncoded()).toString());
            X509CertificateHolder holder = signCert(caCert.getSubjectX500Principal().getEncoded(),
                    pemObjectCsr.getContent(),
                    keyStore, caKey);
            X509Certificate x509Certificate =  new JcaX509CertificateConverter().setProvider( "BC" ).getCertificate( holder );
            logger.info("x509certificate: "+x509Certificate.toString());
            logger.info("cert: "+prettyPrintCert(Base64.encodeBase64String(x509Certificate.getEncoded())));

            Certificate.setCertText(Base64.encodeBase64String(x509Certificate.getEncoded()));
            Certificate.setRevoked(false);
            savedCert = certificateDao.save(Certificate);
            logger.info("getName: "+reverseSubject(x509Certificate.getSubjectX500Principal().getName()));

            insertIpsecRecordsForClient(x509Certificate);
        } catch (Exception e) {
            out.println("Exception: "+e);
            return "Arghh!"; //create a nice error page.
        }
        //session.setAttribute("certAdded", true);

        model.addAttribute("certText",prettyPrintCert(savedCert.getCertText()));
        return "certAdded";
        //return "redirect:/myaccount"; //?purchaseId="+purchaseId;
    }

    private String deleteIpsecRecordsForClient(X509Certificate x509Certificate) {
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

    private void insertIpsecRecordsForClient(X509Certificate x509Certificate) {
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

            X509Certificate serverCert = getServerCert();
            X500Name serverX500Name = subjBytesToX500Name(serverCert.getSubjectX500Principal().getEncoded());/* new X500Name(reverseSubject(serverCert.getSubjectX500Principal().getName()));*/
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


/*
    @RequestMapping(method=RequestMethod.GET, value="/revoke")
    public String revokeCert(Model model, Principal principal, String serial, boolean authError) {
        if(authError) {
            model.addAttribute("password_error", "Your password was wrong. Try again.");
            logger.warn("authError: "+authError);
        }
        long certSerial = Long.valueOf(serial);
        Certificate certificate = certificateDao.findBySerial(certSerial);
        X509CertificateHolder cert = null;
        try {
            PemReader pemReaderCert = new PemReader(new StringReader(prettyPrintCert(certificate.getCertText())));
            PemObject pemObjectCert = pemReaderCert.readPemObject();
            cert = new X509CertificateHolder(pemObjectCert.getContent());
        } catch (Exception e) {
            logger.error("exception "+e);
        }
        model.addAttribute("username", principal.getName());
        model.addAttribute("certInfo", printBasicCertInfo(cert));
        model.addAttribute("certificate", certificate);
        return "revoke";

    }

    @RequestMapping(method=RequestMethod.POST, value="/revoke")
    public String postRevokeCert(Model model, Principal principal, String serial, String password, int reason) {
        Security.addProvider(new BouncyCastleProvider());

        if(usersDao.findByUsername(principal.getName()) != null) {
            logger.debug("password: "+password);
            Users user = usersDao.findByUsername(principal.getName());
            String hashedPassword = Util.getHashedPassword(password, user.getSalt());

            if ( !hashedPassword.equals(user.getPassword())) {
                logger.warn("invalid password when trying to revoke cert");
                return "redirect:/revoke?serial="+serial+"&authError=true";
            } else {
                logger.debug("password was good");
            }
        } else {
            hashPass(password);
            System.out.println("User not found");
            return null;
        }

        try {
            X509v2CRLBuilder crlGen = new X509v2CRLBuilder(new X500Name("C=US, O=test, CN=testCA"),
                    new Date(System.currentTimeMillis()));
            crlGen.addCRLEntry(BigInteger.valueOf(Long.valueOf(serial)), new Date(System.currentTimeMillis()), reason);
            crlGen.setNextUpdate(new Date(System.currentTimeMillis() + (1 * 86400000L)));

            AlgorithmIdentifier sigAlgId = new DefaultSignatureAlgorithmIdentifierFinder().find("SHA512WithRSAEncryption");
            AlgorithmIdentifier digAlgId = new DefaultDigestAlgorithmIdentifierFinder().find(sigAlgId);
            BcContentSignerBuilder bcContentSignerBuilder = new BcRSAContentSignerBuilder(sigAlgId, digAlgId);

            System.out.println("we are going to try to sign...");
            ContentSigner signer = bcContentSignerBuilder.build(PrivateKeyFactory.createKey(getPrivateKey().getEncoded()));
            X509CRLHolder x509CRLHolder =  crlGen.build(signer);
            Certificate cert = certificateDao.findBySerial(Long.valueOf(serial));
            cert.setRevoked(true);
            certificateDao.save(cert);
            System.out.println("we've signed...");
            System.out.println(prettyPrintCrl(Base64.encodeBase64String(x509CRLHolder.getEncoded())));
            model.addAttribute("revoked", "cert "+serial+" has been revoked.");
        } catch (Exception e) {
            System.out.println("something bad happened in crl");
            System.out.println(e);
        }
        return "revoked";
    }
*/


    @Autowired
    CertificatesDao certificatesDao;

    @Autowired
    CertificateIdentityDao certificateIdentityDao;

    @Autowired
    IkeConfigsDao ikeConfigsDao;

    @Autowired
    PeerConfigsDao peerConfigsDao;

    @Autowired
    ChildConfigsDao childConfigsDao;

    @Autowired
    PeerConfigChildConfigDao peerConfigChildConfigDao;

    @Autowired
    TrafficSelectorsDao trafficSelectorsDao;

    @Autowired
    ChildConfigTrafficSelectorDao childConfigTrafficSelectorDao;

    @Autowired
    UsersDao usersDao;

    @Autowired
    CertificateDao certificateDao;

    @Autowired
    IdentitiesDao identitiesDao;

    @Autowired
    SubscriptionDao subscriptionDao;
}
