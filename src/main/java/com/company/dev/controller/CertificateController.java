package com.company.dev.controller;

import com.company.dev.model.app.domain.Certificate;
import com.company.dev.model.app.domain.Subscription;
import com.company.dev.model.app.domain.Users;
import com.company.dev.model.app.repo.CertificateDao;
import com.company.dev.model.app.repo.SubscriptionDao;
import com.company.dev.model.app.repo.UsersDao;
import com.company.dev.model.ipsec.domain.*;
import com.company.dev.model.ipsec.repo.*;
import com.company.dev.util.CertHelper;
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
import java.util.UUID;

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

    @Autowired
    CertHelper certHelper;

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

            if(certHelper.hasActiveConnection(cert.getSubject())) {
                session.setAttribute("certInUse",true);
                return "redirect:/deleteCert?serial="+serial;
            }

            logger.info("did we delete? "+ certHelper.deleteIpsecRecordsForClient(x509Certificate));
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
        model.addAttribute("certInUse",(session.getAttribute("certInUse")));
        model.addAttribute("username", principal.getName());
        //model.addAttribute("certInfo", printBasicCertInfo(cert));
        model.addAttribute("certificate", certificate);
        model.addAttribute("subscriptionId", certificate.getSubscription().getId());

        session.removeAttribute("invalidPassword");
        session.removeAttribute("certInUse");
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
        List<Certificate> certificates = certificateDao.findBySubscriptionAndSubscription_UsersAndCertTextIsNotNullOrderByDateCreated(
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
                c.setCertText(dateToGMT(cert.getNotAfter())); // TODO display time in GMT
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

        List<Certificate> issuedCertificates = certificateDao
                .findBySubscriptionAndSubscription_UsersAndCertTextIsNotNullOrderByDateCreated(
                    new Subscription(subscriptionId),
                    new Users(principal.getName()));



        Certificate stub = certificateDao.findBySubscriptionAndSubjectIsNotNullAndCsrTextIsNull(new Subscription(subscriptionId));

        String subject = null;
        if (stub != null) {
            subject = stub.getSubject();
        } else {
            UUID subj = UUID.randomUUID();
            Certificate newStub = new Certificate("C=US, O=test, CN="+subj.toString(), new Subscription(subscriptionId));
            Certificate savedStub = certificateDao.save(newStub);
            subject = savedStub.getSubject();
            logger.info("saved cert with subject: "+savedStub.getSubject()+", subscriptionId: "+subscriptionId);
        }

        String command = "sudo openssl genpkey -algorithm RSA -out /etc/ipsec.d/private/vpn_client_key.pem -pkeyopt rsa_keygen_bits:2048\n" +
            "sudo openssl req -new -keyform pem -key /etc/ipsec.d/private/vpn_client_key.pem -subj '"+
            subject.replace(", ","/").replace("C=", "/C=")+"'";
        model.addAttribute("command", command);

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
        Certificate stub = certificateDao.findBySubscriptionAndSubjectIsNotNullAndCsrTextIsNull(new Subscription(subscriptionId));
        if (stub == null) { //TODO flesh this out
            return "redirect:/addCert"; //throw new Exception();
        }
        try {
            Security.addProvider(new BouncyCastleProvider());
            is = new FileInputStream(keystoreLocation);
            KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            keyStore.load(is, "changeit".toCharArray());

            PemReader pemReaderCsr = new PemReader(new StringReader(csr));
            PemObject pemObjectCsr = pemReaderCsr.readPemObject();
            logger.info("the CSR: "+ Base64.encodeBase64String(pemObjectCsr.getContent()));

            BigInteger serial = new BigInteger( 32, new SecureRandom() );

            stub.setDateCreated(new Timestamp(new Date().getTime()));
            stub.setCsrText(Base64.encodeBase64String(pemObjectCsr.getContent()));
            stub.setSigned(false);
            stub.setSerial(serial.longValue());
            Certificate Certificate = certificateDao.save(stub);
            /*Certificate certificate = new Certificate(new Timestamp(new Date().getTime()),
                    Base64.encodeBase64String(pemObjectCsr.getContent()), false,
                    subscriptionDao.findByIdAndUsers(subscriptionId, new Users(principal.getName())), serial.longValue());
            Certificate Certificate = certificateDao.save(certificate);
            */

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
            certHelper.insertIpsecRecordsForClient(x509Certificate, keystoreLocation);
        } catch (Exception e) {
            out.println("Exception: "+e);
            return "Arghh!"; //create a nice error page.
        }
        //session.setAttribute("certAdded", true);

        model.addAttribute("certText",prettyPrintCert(savedCert.getCertText()));
        model.addAttribute("subscriptionId", subscriptionId);
        return "certAdded";
        //return "redirect:/myaccount"; //?purchaseId="+purchaseId;
    }

    @Autowired
    UsersDao usersDao;

    @Autowired
    CertificateDao certificateDao;

    @Autowired
    SubscriptionDao subscriptionDao;
}
