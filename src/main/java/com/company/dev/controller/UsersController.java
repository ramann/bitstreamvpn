package com.company.dev.controller;

import com.company.dev.model.app.PaymentPresentation;
import com.company.dev.model.app.SubscriptionPresentation;
import com.company.dev.model.app.domain.Certificate;
import com.company.dev.model.app.domain.Payment;
import com.company.dev.model.app.domain.Subscription;
import com.company.dev.model.app.domain.Users;
import com.company.dev.model.app.repo.CertificateDao;
import com.company.dev.model.app.repo.PaymentDao;
import com.company.dev.model.app.repo.SubscriptionDao;
import com.company.dev.model.app.repo.UsersDao;
import com.company.dev.model.ipsec.domain.*;
import com.company.dev.model.ipsec.repo.*;
import com.company.dev.util.MyBean;
import com.company.dev.util.TimeSpan;
import com.company.dev.util.Util;
import com.github.cage.Cage;
import com.github.cage.YCage;
import com.google.zxing.BarcodeFormat;
import com.google.zxing.EncodeHintType;
import com.google.zxing.MultiFormatWriter;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel;
import org.apache.catalina.servlet4preview.http.HttpServletRequest;
import org.apache.commons.codec.binary.Base64;
import org.bitcoinj.core.*;
//import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.*;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import javax.validation.ConstraintViolation;
import javax.validation.ConstraintViolationException;
import javax.validation.constraints.Pattern;
import javax.validation.constraints.Size;
import javax.xml.bind.DatatypeConverter;
import java.io.*;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.nio.charset.Charset;
import java.security.*;
import java.security.cert.X509Certificate;
import java.sql.Timestamp;
import java.util.*;

import static com.company.dev.util.Util.*;
import static java.lang.System.out;

@Controller
@Validated
public class UsersController {
    private final Logger logger = LoggerFactory.getLogger(this.getClass());

    @RequestMapping(method=RequestMethod.POST, value="/deleteCert")
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
            /*X509v2CRLBuilder crlGen = new X509v2CRLBuilder(new X500Name("C=US, O=test, CN=testCA"),
                    new Date(System.currentTimeMillis()));
            crlGen.addCRLEntry(BigInteger.valueOf(Long.valueOf(serial)), new Date(System.currentTimeMillis()), reason);
            crlGen.setNextUpdate(new Date(System.currentTimeMillis() + (1 * 86400000L)));

            AlgorithmIdentifier sigAlgId = new DefaultSignatureAlgorithmIdentifierFinder().find("SHA512WithRSAEncryption");
            AlgorithmIdentifier digAlgId = new DefaultDigestAlgorithmIdentifierFinder().find(sigAlgId);
            BcContentSignerBuilder bcContentSignerBuilder = new BcRSAContentSignerBuilder(sigAlgId, digAlgId);

            System.out.println("we are going to try to sign...");
            ContentSigner signer = bcContentSignerBuilder.build(PrivateKeyFactory.createKey(getPrivateKey().getEncoded()));
            X509CRLHolder x509CRLHolder =  crlGen.build(signer); */

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

    @RequestMapping(method=RequestMethod.GET, value="/addSubscription")
    public String addSubscription(Model model, Principal principal) {
        logger.info("entered /addSubscription");
        model.addAttribute("username", principal.getName());
        return "addSubscription";
    }

    @RequestMapping(method=RequestMethod.POST, value="/addSubscription")
    public String postAddSubscription(Model model, Principal principal, int duration, HttpServletResponse response) {
        if(Arrays.binarySearch(durations,duration) >= 0) {
            logger.error("duration: "+duration+" is not valid");
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
        }
        Subscription subscription = new Subscription(duration, new BigDecimal(duration*pricePerUnit), new Users(principal.getName()));
        subscriptionDao.save(subscription);
        return "redirect:/myaccount";
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
            logger.info("the CSR: "+Base64.encodeBase64String(pemObjectCsr.getContent()));

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
            return "Arghh!";
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

    @RequestMapping(method=RequestMethod.POST, value="/addPayment")
    public String addPayment(Model model, Principal principal, HttpSession session, int subscriptionId) {
        logger.info("/addPayment");
        Subscription subscription = subscriptionDao.findById(subscriptionId);
        List<Payment> processingPayments = paymentDao.findBySubscriptionAndDateInitiatedIsNotNullAndDateConfirm1IsNullAndInErrorIsFalse(subscription);
        if (processingPayments.size() > 0) {
            return "processingPayments";
        }
        Date now = new Date();
        Timestamp tenMinsAgo = addDuration(new Timestamp(now.getTime()),-10, Calendar.MINUTE);
        Payment savedPendingPayment = null;

        // payments that we haven't seen, that were created within the last 10 minutes
        List<Payment> pendingPayments = paymentDao.findBySubscriptionAndDateInitiatedIsNullAndDateCreatedIsGreaterThan(subscription,
                tenMinsAgo);

        if(pendingPayments.isEmpty()) {
            Address address = MyBean.kit.wallet().freshReceiveAddress();
            Payment newPendingPayment = new Payment(new Timestamp(now.getTime()), address.toString(),
                    subscriptionDao.findById(subscriptionId));
            savedPendingPayment = paymentDao.save(newPendingPayment);
        } else {
            savedPendingPayment = pendingPayments.get(0);
            if(pendingPayments.size() > 1) {
                logger.error("ERROR: there is more than one unconfirmed payment for "+principal.getName());
            }
        }

        //model.addAttribute("subscription", subscription);
        model.addAttribute("username", principal.getName());
        model.addAttribute("paymentAmount", subscription.getPrice());
        model.addAttribute("subscriptionId", subscriptionId);
        model.addAttribute("dateCreated", dateToGMT(savedPendingPayment.getDateCreated()));
        model.addAttribute("dateDue", dateToGMT(addDuration(savedPendingPayment.getDateCreated(),10, Calendar.MINUTE)));
        model.addAttribute("pendingPayment", savedPendingPayment.getReceivingAddress());
        return "addPayment";
    }

    @RequestMapping(method=RequestMethod.GET, value="/payments")
    public String payments(Model model, Principal principal, HttpSession session, int subscriptionId) {
        logger.info("/payments for subscriptionId: "+subscriptionId);

        Subscription subscription = subscriptionDao.findById(subscriptionId);
        Date now = new Date();
        Timestamp tenMinsAgo = addDuration(new Timestamp(now.getTime()),-10, Calendar.MINUTE);
        logger.info("ten minutes ago: "+tenMinsAgo);
        // mark payments not received on time as "in error"
        // TODO: this can be moved somewhere else
        List<Payment> paymentsNotReceivedInTime = paymentDao.findBySubscriptionAndDateInitiatedIsNullAndInErrorIsFalseAndDateCreatedIsLessThanEqual(subscription,
                tenMinsAgo);
        logger.info("paymentsNotReceivedInTime: "+paymentsNotReceivedInTime.size());
        for(Payment p: paymentsNotReceivedInTime) {
            p.setInError(true);
            paymentDao.save(p);
        }


        List<Payment> confirmedPayments = paymentDao.findBySubscriptionAndDateConfirm1IsNotNullAndInErrorIsFalseOrderByDateConfirm1Desc(subscription);
        List<Payment> processingPayments = paymentDao.findBySubscriptionAndDateInitiatedIsNotNullAndDateConfirm1IsNullAndInErrorIsFalse(subscription);
        List<PaymentPresentation> processingPaymentPresentations = new ArrayList<PaymentPresentation>();
        for (Payment p: processingPayments) {
            processingPaymentPresentations.add(new PaymentPresentation(p,dateToGMT(p.getDateCreated())));
        }

        List<PaymentPresentation> confirmedPaymentPresentations = new ArrayList<PaymentPresentation>();
        for(Payment p:confirmedPayments) {
            confirmedPaymentPresentations.add(new PaymentPresentation(p,dateToGMT(p.getDateCreated())));
        }
        logger.info("principal.getName:"+principal.getName()+
                ", confirmedPayments: "+confirmedPayments.size());

        model.addAttribute("subscriptionId", subscriptionId);
        model.addAttribute("confirmedPaymentPresentations", confirmedPaymentPresentations);
        model.addAttribute("processingPaymentPresentations", processingPaymentPresentations);
        //model.addAttribute("confirmedPayments", confirmedPayments);
        model.addAttribute("confirmedPaymentsSize", confirmedPayments.size());
        model.addAttribute("processingPaymentsSize", processingPayments.size());
        model.addAttribute("username",principal.getName());
        return "payments";
    }

    @RequestMapping(method=RequestMethod.GET, value="/myaccount")
    public String myAccount(Model model, Principal principal, HttpSession session)
    {
        logger.info("/myaccount");

        List<Subscription> subscriptions = subscriptionDao.findByUsers(new Users(principal.getName()));
        List<SubscriptionPresentation> subscriptionPresentations = new ArrayList<SubscriptionPresentation>(subscriptions.size());
        for (Subscription s : subscriptions) {
            /*List<Payment> payments = paymentDao.findBySubscriptionOrderByDateConfirm1Desc(s);
            if (payments == null || payments.size() == 0 || payments.get(0).getDateConfirm1() == null) {
                s.setTitle("inactive");
            } else {
                Calendar cal = Calendar.getInstance();
                cal.setTime(payments.get(0).getDateConfirm1());
                cal.add(Calendar.HOUR_OF_DAY, s.getDuration());

                // for a subscription to be active, "now" needs to be less than the most recent payment + duration
                if (new Date().before(cal.getTime())) {
                    s.setTitle("active");
                } else {
                    s.setTitle("inactive");
                }
            }*/
            List<Payment> payments = paymentDao.findBySubscriptionAndDateConfirm1IsNotNullAndInErrorIsFalseOrderByDateConfirm1(s);
            List<TimeSpan> timeSpans = new ArrayList<TimeSpan>();
            for(int i=0; i<payments.size(); i++) {
                Timestamp thisDateConfirm1 = payments.get(i).getDateConfirm1();
                Timestamp thisDateConfirm1PlusDuration = addDuration(thisDateConfirm1, s.getDuration(), Calendar.HOUR_OF_DAY);

                if (i==0) {
                    timeSpans.add(new TimeSpan(thisDateConfirm1,thisDateConfirm1PlusDuration));
                } else {
                    if (thisDateConfirm1.before(timeSpans.get(i-1).getEnd())) {
                        Timestamp begin = timeSpans.get(i-1).getEnd();
                        Timestamp end = addDuration(timeSpans.get(i-1).getEnd(), s.getDuration(), Calendar.HOUR_OF_DAY);
                        timeSpans.add(new TimeSpan(begin, end));
                    } else {
                        timeSpans.add(new TimeSpan(thisDateConfirm1, thisDateConfirm1PlusDuration));
                    }
                }
            }
            logger.warn("timeSpans.size:"+timeSpans.size());
            for(TimeSpan t:timeSpans) {
                logger.warn(t.toString());
            }

            boolean isActive = false;
            String activeUntil = "";
            for (int i=timeSpans.size()-1; i>=0 && !isActive; i--) {
                Date now = new Date();
                TimeSpan t = timeSpans.get(i);
                logger.error(t.toString());
                if (now.before(t.getEnd())) {
                    isActive = true;
                    activeUntil = "active (until " + dateToGMT(t.getEnd())+")";
                    logger.warn(activeUntil);
                }
            }
            //s.setTitle(isActive ? "active" : "inactive");
            s.setDuration(s.getDuration() / 24);
            subscriptionPresentations.add(new SubscriptionPresentation(s,isActive, activeUntil));
        }


/*
        List<Certificate> certificates = certificateDao.findByUsers(new Users(principal.getName()));
        for(Certificate c:certificates) {
            try {
                PemReader pemReaderCert = new PemReader(new StringReader(prettyPrintCert(c.getCertText())));
                PemObject pemObjectCert = pemReaderCert.readPemObject();
                X509CertificateHolder cert = new X509CertificateHolder(pemObjectCert.getContent());
                c.setCertText("serial: "+cert.getSerialNumber()+"\n"+
                        "subject: "+ cert.getSubject().toString()+"\n"+
                        "creation date: " + dateToGMT(cert.getNotBefore())+"\n"+
                        "expiration date: "+dateToGMT(cert.getNotAfter())); // TODO display time in GMT
                System.out.println("c:"+c.getCertText());
            } catch (Exception e) {
                logger.error("Error reading pem of CSR or cert");
                logger.error(e.toString());
            }
        }
*/

        model.addAttribute("subscriptionPresentations", subscriptionPresentations);
        model.addAttribute("subscriptionPresentationsSize", subscriptionPresentations.size());

        model.addAttribute("subscriptions", subscriptions);
        model.addAttribute("subscriptionsSize", subscriptions.size());
        /**
         * certAdded and certDeleted should really never be false - only null or true
         */
        model.addAttribute("certAdded",(session.getAttribute("certAdded")!=null) ? session.getAttribute("certAdded") : false);
        model.addAttribute("certDeleted",(session.getAttribute("certDeleted")!=null) ? session.getAttribute("certDeleted") : false);

/*        model.addAttribute("certificates", certificates);
        model.addAttribute("certificatesSize",certificates.size());
        */
        model.addAttribute("username", principal.getName());
        model.addAttribute("page", "myaccount");
        session.removeAttribute("certAdded");
        session.removeAttribute("certDeleted");
        return "myaccount";
    }


    @RequestMapping(method=RequestMethod.GET, value="/createaccount")
    public String createAccount(Users users, Model model)
    {
        model.addAttribute("page", "createaccount");
        return "createaccount";
    }

    @ExceptionHandler(value = { ConstraintViolationException.class })
    @ResponseStatus(value = HttpStatus.BAD_REQUEST)
    public String validateAccountSetup(ConstraintViolationException e, Model model, HttpServletRequest request, HttpSession session) {
        Set<ConstraintViolation<?>> violations = e.getConstraintViolations();
        StringBuilder strBuilder = new StringBuilder();
        for (ConstraintViolation<?> violation : violations ) {
            strBuilder.append(violation.getMessage() + "\n");
            if(violation.getMessage().contains("Username")) {
                out.println("username_error");
                model.addAttribute("username_error", violation.getMessage());
                model.addAttribute("username", "");
            }
            if(violation.getMessage().contains("Password confirmation")) {
                model.addAttribute("password_confirm_error", violation.getMessage());
            }
            if(violation.getMessage().contains("Password must")) {
                model.addAttribute("password_error", violation.getMessage());
            }
            if(violation.getMessage().contains("CAPTCHA")) {
                model.addAttribute("captcha_error", violation.getMessage());
            }
        }

        if (!model.containsAttribute("password_error") &&
                !model.containsAttribute("password_confirm_error") &&
                !request.getParameter("password").equals(request.getParameter("confirmPassword"))) {
            model.addAttribute("password_confirm_error", "Password and password confirmation are not equal");
        }
        if (!model.containsAttribute("captcha_error") &&
                !request.getParameter("captcha").equals(session.getAttribute("captchaToken"))) {
            model.addAttribute("captcha_error", "CAPTCHA value didn't match.");
        }

        if(!model.containsAttribute("username_error")) {
            model.addAttribute("username", request.getParameter("username"));
        }

        session.setAttribute("captchaToken", null);

        return "createaccount";
    }

    @RequestMapping(method=RequestMethod.POST, value="/createaccount")
    public String accountSetup(@Pattern(regexp="^[a-zA-Z0-9]{3,10}$", message="Username must be 3 to 10 alphanumeric characters")
                                                String username,
                                    /*@Pattern(regexp="^(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=.*\\p{Punct}).{4,10}$",
                                            message="Password must be between 4 and 10 characters long and contain a lowercase, uppercase, numeral, and punctuation character.")*/
                               @Size(min=4, max=10, message="Password must be 4 to 10 characters")
                                            String password,
                                    /*@Pattern(regexp="^(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=.*\\p{Punct}).{4,10}$",
                                            message="Password must be between 4 and 10 characters long and contain a lowercase, uppercase, numeral, and punctuation character.")*/
                                    /* @Pattern(regexp="^{4,10}$", message="Password confirmation didn't match") */
                                                String confirmPassword,
                                    /*@Pattern(regexp="^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$", message="You must enter a Bitcoin address")
                                                String btc,*/
                                    /*@Size(min=7, max=7, message="CAPTCHA value is wrong.")*/ String captcha,
                                    Model model, HttpSession session) //String confirm_password, String btc, Model model,HttpSession session,
    {
        // We do this validation here because the annotations above won't catch these.
        boolean errors = false;
        if( !captcha.equals(session.getAttribute("captchaToken"))) {
            model.addAttribute("captcha_error", "It looks like you've entered the wrong CAPTCHA value, here's a different one to try.");
            errors = true;
        }
        if( !password.equals(confirmPassword)) {
            model.addAttribute("password_confirm_error", "Password and password confirmation are not equal");
            errors = true;
        }
        if (usersDao.findByUsername(username) != null) {
            model.addAttribute("username_exists_error", "Username has already been taken");
            errors = true;
        } else {
            model.addAttribute("username", username);
        }
        if(errors) {
            return "createaccount";
        }

        Users user = null;
        try {
            user = new Users(username, password);
            usersDao.save(user);
            session.setAttribute("username", username);
        }
        catch (Exception ex) {
            logger.error("Error creating the user: " + ex.toString());
        }
        logger.info("User succesfully created! (id = " + user.getUsername() + ")");

        return "redirect:/accountcreated";
    }

    @RequestMapping(method=RequestMethod.GET, value="accountcreated")
    public String accountCreated(Model model, HttpSession session) {
        logger.info("/accountcreated");
        model.addAttribute("username", session.getAttribute("username"));
        session.setAttribute("username", null);
        return "accountcreated";
    }

    @RequestMapping(method=RequestMethod.GET, value="/qrcode")
    public void qrcode(Principal principal, HttpServletResponse response, HttpSession session, int subscriptionId) {
        logger.info("entered /qrcode");
        Subscription subscription = subscriptionDao.findById(subscriptionId);
        List<Payment> unconfirmedPayments = paymentDao.findBySubscriptionAndDateConfirm1IsNull(subscription);

        String qrCodeData = "bitcoin:"+unconfirmedPayments.get(0).getReceivingAddress()+"?amount="+subscription.getPrice(); // +"?amount=0.1234";
        int qrCodeWidth = 200;
        int qrCodeHeight = 200;
        Map<EncodeHintType, ErrorCorrectionLevel> hintMap = new HashMap<EncodeHintType, ErrorCorrectionLevel>();
        hintMap.put(EncodeHintType.ERROR_CORRECTION, ErrorCorrectionLevel.L);

        try {
            BitMatrix matrix = new MultiFormatWriter().encode(qrCodeData, BarcodeFormat.QR_CODE, qrCodeWidth, qrCodeHeight, hintMap);
            response.setContentType("image/jpeg");
            MatrixToImageWriter.writeToStream(matrix, "jpg", response.getOutputStream());
            response.flushBuffer();
        } catch (Exception ex) {
            logger.error("Failed to write QRcode to output stream.");
            throw new RuntimeException("IOError writing QRcode to output stream");
        }
    }

    @RequestMapping(method=RequestMethod.GET, value = "/")
    public String index(String filename, Model model) {
        String msg = "-------------------------- TESTING LOG ENTRY --------------------------";
        logger.error(msg);
        logger.warn(msg);
        logger.info(msg);
        logger.trace(msg);
        logger.debug(msg);
        return "index";
    }

    @RequestMapping(method=RequestMethod.GET, value = "/layout")
    public String layout(Model model) {
        return "layout";
    }

    @RequestMapping(method=RequestMethod.GET, value = "/header")
    public String header(Model model) {
        return "header";
    }

    @RequestMapping(method=RequestMethod.GET, value = "/footer")
    public String footer(Model model) {
        return "footer";
    }

    @RequestMapping("/greeting")
    public String greeting(@RequestParam(value="name", required=false, defaultValue="World") String name, Model model, HttpSession session) {
        model.addAttribute("name", name);
        model.addAttribute("captchaToken", session.getAttribute("captchaToken"));
        return "greeting";
    }
    // ------------------------
    // PUBLIC METHODS
    // ------------------------

    @RequestMapping(method=RequestMethod.GET, value = "/resetpassword")
    public String resetPassword(Model model) {
        return "resetpassword";
    }

    @RequestMapping(method=RequestMethod.POST, value="/resetpassword")
    public String resetPassword(String password1, String password2, Model model) {
        return "fix me";
    }

    @RequestMapping(method=RequestMethod.GET, value = "/viewproducts")
    public String viewProducts(Model model) {
        logger.info("GET /viewproducts");
        return "viewproducts";
    }

    @RequestMapping(method=RequestMethod.GET, value = "/login")
    public String login(Model model) {
        logger.info("GET /login");
        return "login";
    }

    @RequestMapping(method=RequestMethod.POST, value = "/login")
    public String loginPost(String username, String password, HttpSession session, Model model) {
        logger.info("POST /login");
       /* try {*/
        if (usersDao.findByUsername(username) != null) {
            logger.debug("username: " + username + ", password: " + password);
            Users user = usersDao.findByUsername(username);
            String hashedPassword = Util.getHashedPassword(password, user.getSalt());

            if (!hashedPassword.equals(user.getPassword())) {
                logger.warn("invalid login");
                return "redirect:/login";
            }
            session.setAttribute("username", user.getUsername());
            logger.info("/login username---->" + username);
/*
        } catch (Exception ex) {
*/
        } else {
            SecureRandom random = new SecureRandom();
            byte slt[] = new byte[8];
            random.nextBytes(slt);
            Util.getHashedPassword(password, Base64.encodeBase64String(slt));

            logger.warn("User not found");
            return "redirect:/login";
        }
        return "viewproducts";
    }

    /**
     * /create  --> Create a new user and save it in the database.
     *
     * @param username User's email
     * @param password User's name
     * @return A string describing if the user is succesfully created or not.
     */
    @RequestMapping("/create")
    @ResponseBody
    public String create(String username, String password, Model model) {
        Users user = null;
        try {
            user = new Users(username, password);
            usersDao.save(user);
        }
        catch (Exception ex) {
            return "Error creating the user: " + ex.toString();
        }
        return "User succesfully created! (id = " + user.getUsername() + ")";
    }

    /**
     * /delete  --> Delete the user having the passed id.
     *
     * @param username The id of the user to delete
     * @return A string describing if the user is succesfully deleted or not.
     */
    @RequestMapping("/delete")
    @ResponseBody
    public String delete(String username) {
        try {
            Users user = new Users(username);
            usersDao.delete(user);
        }
        catch (Exception ex) {
            return "Error deleting the user: " + ex.toString();
        }
        return "User successfully deleted!";
    }

    /**
     * /get-by-email  --> Return the id for the user having the passed email.
     *
     * @param username The email to search in the database.
     * @return The user id or a message error if the user is not found.
     */
    @RequestMapping("/get-by-username")
    @ResponseBody
    public String getByEmail(String username) {
        String userId;
        try {
            Users user = usersDao.findByUsername(username);
            userId = String.valueOf(user.getUsername());
        }
        catch (Exception ex) {
            return "User not found";
        }
        return "The user id is: " + userId;
    }

    /**
     * /update  --> Update the email and the name for the user in the database
     * having the passed id.
     *
     * @param username The id for the user to update.
     * @param password The new email.
     * @param salt The new name.
     * @return A string describing if the user is succesfully updated or not.
     */
    @RequestMapping("/update")
    @ResponseBody
    public String updateUser(String username, String password, String salt) {
        try {
            Users user = usersDao.findByUsername(username);
            user.setPassword(password);
            user.setSalt(salt);
            usersDao.save(user);
        }
        catch (Exception ex) {
            return "Error updating the user: " + ex.toString();
        }
        return "User succesfully updated!";
    }

    /**
     * Generates captcha as image and returns the image path
     * stores the captcha code in the http session
     * and deletes older, unused captcha images.
     */
    @RequestMapping(value = "/generatecaptcha", method = RequestMethod.GET)
    public void generateCaptcha(Model model, HttpServletResponse response, HttpSession session) { //ResponseEntity<CaptchaRequestData> generateCaptcha(HttpSession session) {
        Cage currGcage = new YCage();
        String captchaToken = currGcage.getTokenGenerator().next();
        logger.debug("captchaToken: "+captchaToken);

        //Setting the captcha token in http session
        session.setAttribute("captchaToken", captchaToken);

        response.setContentType("image/jpeg");
        try {
            OutputStream os = response.getOutputStream();
            currGcage.draw(captchaToken, os);

            response.flushBuffer();
        } catch (IOException ex) {
            logger.error("Error writing captcha to output stream.");
            throw new RuntimeException("IOError writing file to output stream");
        }
    }

    // ------------------------
    // PRIVATE FIELDS
    // ------------------------

    @Autowired
    private UsersDao usersDao;

    @Autowired
    private PaymentDao paymentDao;

    @Autowired
    CertificateDao certificateDao;

    @Autowired
    IdentitiesDao identitiesDao;

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
    SubscriptionDao subscriptionDao;
} // class UserController
