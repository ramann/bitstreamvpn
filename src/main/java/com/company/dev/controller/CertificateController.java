package com.company.dev.controller;

import com.company.dev.model.app.domain.Certificate;
import com.company.dev.model.app.domain.Subscription;
import com.company.dev.model.app.domain.Users;
import com.company.dev.model.app.repo.CertificateDao;
import com.company.dev.model.app.repo.SubscriptionDao;
import com.company.dev.model.app.repo.UsersDao;
import com.company.dev.model.ipsec.domain.*;
import com.company.dev.model.ipsec.repo.*;
import com.company.dev.util.ForbiddenException;
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
import org.springframework.beans.factory.annotation.Value;
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
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.charset.Charset;
import java.security.*;
import java.security.cert.X509Certificate;
import java.sql.Timestamp;
import java.util.Arrays;
import java.util.Date;
import java.util.List;

import static com.company.dev.util.Util.*;
import static com.company.dev.util.Util.dateToGMT;
import static java.lang.System.out;

@Controller
public class CertificateController {
    private final Logger logger = LoggerFactory.getLogger(this.getClass());

    @Value("${keystore.location}")
    public String keystoreLocation;

    @Value("${app.dev}")
    public boolean appDev;

    @RequestMapping(method= RequestMethod.POST, value="/deleteCert")
    public String postDeleteCert(Model model, Principal principal, String serial, String password, HttpSession session) {
        Security.addProvider(new BouncyCastleProvider());

        Certificate cert = certificateDao.findBySerialAndSubscription_Users(Long.valueOf(serial), new Users(principal.getName()));
        if (appDev || cert == null) {
            throw new ForbiddenException(errorText(Certificate.class.getName(), serial, principal.getName())); //"Could not find certificate with serial number "+serial+", for user: "+principal.getName());
        }

        if(usersDao.findByUsername(principal.getName()) != null) {
            logger.debug("password: "+password);
            Users user = usersDao.findByUsername(principal.getName());
            byte[] hashedPassword = Util.getHashedPassword(password, user.getSalt());

            if (!Arrays.equals(hashedPassword, user.getPassword())) {
                logger.warn("invalid password when trying to delete cert");
                session.setAttribute("invalidPassword",true);
                return "redirect:/deleteCert?serial="+serial;
            } else {
                logger.debug("password was good");
            }
        } else {
            hashPass(password);
            logger.error("User "+principal.getName()+" not found");
            return null;
        }

        try {
            PemReader pemReaderCert = new PemReader(new StringReader(prettyPrintCert(cert.getCertText())));
            PemObject pemObjectCert = pemReaderCert.readPemObject();
            X509CertificateHolder x509CertificateHolder = new X509CertificateHolder(pemObjectCert.getContent());
            X509Certificate x509Certificate =  new JcaX509CertificateConverter().setProvider( "BC" ).getCertificate( x509CertificateHolder );
            logger.info("did we delete? "+ deleteIpsecRecordsForClient(x509Certificate));
            certificateDao.delete(cert);
            logger.info("we've deleted...");
            //logger.debug(prettyPrintCrl(Base64.encodeBase64String(x509CRLHolder.getEncoded())));
            model.addAttribute("revoked", "cert "+serial+" has been deleted.");
        } catch (Exception e) {
            logger.error("something bad happened trying to delete cert with serial:"+serial,e);
            return "error deleting cert";
        }
        session.setAttribute("certDeleted",true);
        return "redirect:/myaccount";
    }

    @RequestMapping(method=RequestMethod.GET, value="/deleteCert")
    public String deleteCert(Model model, Principal principal, String serial, HttpSession session){
        Certificate certificate = certificateDao.findBySerialAndSubscription_Users(Long.valueOf(serial), new Users(principal.getName()));
        if (appDev || certificate == null) {
            throw new ForbiddenException(errorText(Certificate.class.getName(), String.valueOf(serial), principal.getName()));
        }
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
    public void downloadCert(Principal principal, String serial, HttpServletResponse response) {
        Certificate certificate = certificateDao.findBySerialAndSubscription_Users(Long.valueOf(serial), new Users(principal.getName()));
        if (certificate == null) {
            throw new ForbiddenException(errorText(Certificate.class.getName(), String.valueOf(serial), principal.getName()));
        }
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
        if (subscriptionDao.findByIdAndUsers(subscriptionId, new Users(principal.getName())) == null) {
            throw new ForbiddenException(errorText(Subscription.class.getName(), String.valueOf(subscriptionId), principal.getName()));
        }
        List<Certificate> certificates = certificateDao.findBySubscriptionAndSubscription_UsersOrderByDateCreated(
                new Subscription(subscriptionId), new Users(principal.getName()));

        for(Certificate c:certificates) {
            try {
                PemReader pemReaderCsr = new PemReader(new StringReader(prettyPrintCsr(c.getCsrText())));
                PemObject pemObjectCsr = pemReaderCsr.readPemObject();
                PKCS10CertificationRequest pkcs10CertificationRequest = new PKCS10CertificationRequest(pemObjectCsr.getContent());
                logger.debug("cert req: "+pkcs10CertificationRequest.getSubject());
                c.setCsrText(pkcs10CertificationRequest.getSubject().toString());

                PemReader pemReaderCert = new PemReader(new StringReader(prettyPrintCert(c.getCertText())));
                PemObject pemObjectCert = pemReaderCert.readPemObject();
                X509CertificateHolder cert = new X509CertificateHolder(pemObjectCert.getContent());
                c.setCertText("serial: "+cert.getSerialNumber()+"\n"+
                        "subject: "+ cert.getSubject().toString()+"\n"+
                        "expires on "+dateToGMT(cert.getNotAfter())); // TODO display time in GMT
                logger.debug("c:"+c.getCertText());
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
        if(subscriptionDao.findByIdAndUsers(subscriptionId, new Users(principal.getName())) == null) {
            throw new ForbiddenException(errorText(Subscription.class.getName(), String.valueOf(subscriptionId), principal.getName()));
        }
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
        if (subscriptionDao.findByIdAndUsers(subscriptionId, new Users(principal.getName())) == null) {
            throw new ForbiddenException(errorText(Subscription.class.getName(), String.valueOf(subscriptionId), principal.getName()));
        }
        logger.info("das CSR: "+csr);
        FileInputStream is;
        Certificate savedCert = null;
        try {
            Security.addProvider(new BouncyCastleProvider());
            logger.debug("found payment!");
            is = new FileInputStream(keystoreLocation);
            KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            keyStore.load(is, "changeit".toCharArray());

            PemReader pemReaderCsr = new PemReader(new StringReader(csr));
            PemObject pemObjectCsr = pemReaderCsr.readPemObject();
            logger.info("the CSR: "+ Base64.encodeBase64String(pemObjectCsr.getContent()));

            BigInteger serial = new BigInteger( 32, new SecureRandom() );
            Certificate certificate = new Certificate(new Timestamp(new Date().getTime()),
                    Base64.encodeBase64String(pemObjectCsr.getContent()), false,
                    subscriptionDao.findByIdAndUsers(subscriptionId, new Users(principal.getName())), serial.longValue());
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
            Certificate.setDateInitiated(new Timestamp(new Date().getTime()));
            savedCert = certificateDao.save(Certificate);
            logger.info("getName: "+reverseSubject(x509Certificate.getSubjectX500Principal().getName()));

            insertIpsecRecordsForClient(x509Certificate, keystoreLocation);
        } catch (Exception e) {
            out.println("Exception: "+e);
            return "Arghh!"; //create a nice error page.
        }
        //session.setAttribute("certAdded", true);

        model.addAttribute("certText",prettyPrintCert(savedCert.getCertText()));
        return "certAdded";
        //return "redirect:/myaccount"; //?purchaseId="+purchaseId;
    }

    String deleteIpsecRecordsForClient(X509Certificate x509Certificate) {
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

    void insertIpsecRecordsForClient(X509Certificate x509Certificate, String keystoreLocation) {
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

            ChildConfigs childConfigs = new ChildConfigs("rw", "/usr/local/libexec/ipsec/_updown iptables"); // TODO: this script should be default
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
    UsersDao usersDao;

    @Autowired
    CertificateDao certificateDao;

    @Autowired
    SubscriptionDao subscriptionDao;
}
