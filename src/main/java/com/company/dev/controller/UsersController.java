package com.company.dev.controller;

import com.company.dev.model.*;
import com.company.dev.model.Certificate;
import com.company.dev.util.MyBean;
import com.company.dev.util.Util;
import com.github.cage.Cage;
import com.github.cage.GCage;
import com.github.cage.YCage;
import com.google.common.util.concurrent.FutureCallback;
import com.google.common.util.concurrent.Futures;
import com.google.zxing.BarcodeFormat;
import com.google.zxing.EncodeHintType;
import com.google.zxing.MultiFormatWriter;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel;
import org.apache.catalina.servlet4preview.http.HttpServletRequest;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.io.IOUtils;
import org.apache.tomcat.jni.Time;
import org.bitcoinj.core.*;
import org.bitcoinj.kits.WalletAppKit;
import org.bitcoinj.params.RegTestParams;
import org.bitcoinj.wallet.Wallet;
import org.bitcoinj.wallet.listeners.WalletCoinsReceivedEventListener;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.*;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.provider.PEMUtil;
import org.bouncycastle.openssl.PEMDecryptor;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.bc.BcContentSignerBuilder;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;
import org.bouncycastle.operator.bc.BcRSAContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.bouncycastle.x509.X509V2CRLGenerator;
import org.hibernate.validator.constraints.NotBlank;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.validation.FieldError;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;
import org.thymeleaf.util.DateUtils;
import sun.misc.BASE64Encoder;
import sun.security.provider.X509Factory;

import javax.security.auth.x500.X500Principal;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import javax.validation.ConstraintViolation;
import javax.validation.ConstraintViolationException;
import javax.validation.Path;
import javax.validation.Valid;
import javax.validation.constraints.Pattern;
import javax.validation.constraints.Size;
import javax.validation.metadata.ConstraintDescriptor;
import java.io.*;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.X509Certificate;
import java.sql.Timestamp;
import java.util.*;

import org.bouncycastle.asn1.x509.*;

import static com.company.dev.util.Util.*;
import static java.lang.System.out;

@Controller
@Validated
public class UsersController {

    @RequestMapping(method=RequestMethod.GET, value="/revoke")
    public String revokeCert(Model model, Principal principal, String serial, boolean authError) {
        System.out.println("authError: "+authError);
        if(authError) {
            model.addAttribute("password_error", "Your password was wrong. Try again.");
        }
        model.addAttribute("username", principal.getName());
        long certSerial = Long.valueOf(serial);
        Certificate certificate = certificateDao.findBySerial(certSerial);
        //certificate.setCertText(prettyPrintCert(certificate.getCertText()));
        X509CertificateHolder cert = null;
        try {
            PemReader pemReaderCert = new PemReader(new StringReader(prettyPrintCert(certificate.getCertText())));
            PemObject pemObjectCert = pemReaderCert.readPemObject();
            cert = new X509CertificateHolder(pemObjectCert.getContent());
        } catch (Exception e) {
            System.out.println("exception ");
        }
        model.addAttribute("certInfo", printBasicCertInfo(cert));
        model.addAttribute("certificate", certificate);
        return "revoke";

    }

    @RequestMapping(method=RequestMethod.POST, value="/revoke")
    public String postRevokeCert(Model model, Principal principal, String serial, String password, int reason) {

        Security.addProvider(new BouncyCastleProvider());

        try {
            System.out.println("password: "+password);
            Users user = usersDao.findByUsername(principal.getName());
            String hashedPassword = Util.getHashedPassword(password, user.getSalt());

            if ( !hashedPassword.equals(user.getPassword())) {
                System.out.println("invalid login");
                //model.addAttribute("password_error", "Your password was wrong. Try again.");
                //model.addAttribute("serial", serial);
                return "redirect:/revoke?serial="+serial+"&authError=true";
            } else {
                System.out.println("password was good");
            }
        } catch (Exception ex) {
            SecureRandom random = new SecureRandom();
            byte slt[] = new byte[8];
            random.nextBytes(slt);
            Util.getHashedPassword(password, Base64.encodeBase64String(slt));

            System.out.println("User not found");
            return null;
        }

        try {
            BigInteger certSerial = BigInteger.valueOf(Long.valueOf(serial));

            InputStream is = new FileInputStream("/home/ram/pki-java/server.keystore");

            KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            keyStore.load(is, "changeit".toCharArray());
            String alias = "javaalias";

            PrivateKey caKey = (PrivateKey) keyStore.getKey(alias, "changeit".toCharArray());

            X509v2CRLBuilder crlGen = new X509v2CRLBuilder(new X500Name("O=Company Name, OU=Signing CA, CN=website.example"),
                    new Date(System.currentTimeMillis()));
            crlGen.addCRLEntry(certSerial, new Date(System.currentTimeMillis()), reason);
            crlGen.setNextUpdate(new Date(System.currentTimeMillis() + (1 * 86400000L)));
            AsymmetricKeyParameter privateKeyAsymKeyParam = PrivateKeyFactory.createKey(caKey.getEncoded());

            AlgorithmIdentifier sigAlgId = new DefaultSignatureAlgorithmIdentifierFinder().find("SHA512WithRSAEncryption");
            AlgorithmIdentifier digAlgId = new DefaultDigestAlgorithmIdentifierFinder().find(sigAlgId);
            BcContentSignerBuilder bcContentSignerBuilder = new BcRSAContentSignerBuilder(sigAlgId, digAlgId);

            System.out.println("we are going to try to sign...");
            ContentSigner signer = bcContentSignerBuilder.build(privateKeyAsymKeyParam);
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

    @RequestMapping(method=RequestMethod.GET, value="/certs")
    public String csr(Model model, Principal principal, String purchaseId) {

        int purchaseInt = Integer.valueOf(purchaseId);
        Purchase purchase = purchaseDao.findById(purchaseInt);

        List<Certificate> certificates = certificateDao.findByPurchase(purchase);
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

            }
        }
        model.addAttribute("certificates", certificates);
        model.addAttribute("certificatesSize", certificates.size());
        model.addAttribute("purchaseId", purchaseId);
        model.addAttribute("username", principal.getName());
        return "certs";
    }

    @RequestMapping(method=RequestMethod.POST, value="/certs")
    public String postCSR(Model model, Principal principal, String csr, String purchaseId) {
        model.addAttribute("username", principal.getName());
        out.println("das CSR: "+csr);
        out.println("purchaseId: "+purchaseId);
        FileInputStream is;
        try {
            Purchase purchase = purchaseDao.findById(Integer.valueOf(purchaseId));
            System.out.println("found purchase!");
            is = new FileInputStream("/home/ram/pki-java/server.keystore");

            Security.addProvider(new BouncyCastleProvider());

        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        keyStore.load(is, "changeit".toCharArray());
        String alias = "javaalias";

        PrivateKey caKey = (PrivateKey) keyStore.getKey("javaalias", "changeit".toCharArray());
        X509Certificate cacert = (X509Certificate) keyStore.getCertificate("javaalias");

        PemReader pemReader = new PemReader(new StringReader(csr));
        PemObject pemObject = pemReader.readPemObject();
        System.out.println("pemObject created");
        PKCS10CertificationRequest pkcs10CertificationRequest = new PKCS10CertificationRequest(pemObject.getContent());
        System.out.println("the content: "+Base64.encodeBase64String(pemObject.getContent()));

            BigInteger serial;
            serial = new BigInteger( 32, new SecureRandom() );

        Certificate certificate = new Certificate(new Timestamp(new Date().getTime()), Base64.encodeBase64String(pemObject.getContent()), false, purchase, serial.longValue());
        Certificate savedCert = certificateDao.save(certificate);
        AlgorithmIdentifier sigAlgId = new DefaultSignatureAlgorithmIdentifierFinder().find( "SHA512withRSA" );
        AlgorithmIdentifier digAlgId = new DefaultDigestAlgorithmIdentifierFinder().find( sigAlgId );
        X500Name issuer;
        //issuer = new X500Name( "O=Company Name, OU=Signing CA, CN=website.example" );
        System.out.println("CA name"+ cacert.getSubjectX500Principal().getName());
        System.out.println("subject reversed: "+ Util.reverseSubject(cacert.getSubjectX500Principal().getName()));
        issuer = new X500Name(Util.reverseSubject(cacert.getSubjectX500Principal().getName()));


        //serial = BigInteger.valueOf(24);

        Date from;
        from = new Date();
        Date to;
         to = new Date( System.currentTimeMillis() + ( 1 * 86400000L ) );

        DigestCalculator digCalc = new BcDigestCalculatorProvider().get( new AlgorithmIdentifier( OIWObjectIdentifiers.idSHA1 ) );
        X509ExtensionUtils x509ExtensionUtils = new X509ExtensionUtils( digCalc );
        X509v3CertificateBuilder certgen;
        certgen = new X509v3CertificateBuilder( issuer, serial, from, to, pkcs10CertificationRequest.getSubject(), pkcs10CertificationRequest.getSubjectPublicKeyInfo() );
            //certgen = new X509v3CertificateBuilder( issuer, serial, from, to, new X500Name("O=Company Name, OU=Server1, CN=website.example"), pkcs10CertificationRequest.getSubjectPublicKeyInfo() );

        certgen.addExtension( Extension.basicConstraints, false, new BasicConstraints( false ) );
        certgen.addExtension(Extension.keyUsage, true, new KeyUsage( KeyUsage.digitalSignature | KeyUsage.keyEncipherment));
        KeyPurposeId[] usages = {KeyPurposeId.id_kp_emailProtection, KeyPurposeId.id_kp_clientAuth};
        certgen.addExtension(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(usages));
        certgen.addExtension(Extension.subjectKeyIdentifier, false, new SubjectKeyIdentifier(new DigestUtils().sha1(pkcs10CertificationRequest.getSubjectPublicKeyInfo().parsePublicKey().getEncoded())));

        X509CertificateHolder caCertHolder = new X509CertificateHolder(keyStore.getCertificate("javaalias").getEncoded());
        DigestCalculator dc = new BcDigestCalculatorProvider().get(new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1));
        AuthorityKeyIdentifier aki =  new X509ExtensionUtils(dc).createAuthorityKeyIdentifier(caCertHolder.getSubjectPublicKeyInfo());
        certgen.addExtension(Extension.authorityKeyIdentifier, false, aki);

        ContentSigner signer = new BcRSAContentSignerBuilder( sigAlgId, digAlgId ).build( PrivateKeyFactory.createKey( caKey.getEncoded() ) );
        X509CertificateHolder holder = certgen.build(signer);

        //Security.addProvider(new BouncyCastleProvider());
        X509Certificate x509Certificate =  new JcaX509CertificateConverter().setProvider( "BC" ).getCertificate( holder );
        out.println("x509certificate: "+x509Certificate.toString());
        System.out.println("encoded: "+Base64.encodeBase64String(x509Certificate.getEncoded()));

        savedCert.setCertText(Base64.encodeBase64String(x509Certificate.getEncoded()));
        savedCert.setRevoked(false);
        certificateDao.save(savedCert);

            String certNice = "";
            BASE64Encoder encoder = new BASE64Encoder();
            certNice += X509Factory.BEGIN_CERT+"\n";
            OutputStream os = new ByteArrayOutputStream();
            encoder.encodeBuffer(x509Certificate.getEncoded(), os);
            certNice += os.toString();
            certNice += X509Factory.END_CERT;
            System.out.println("cert: "+certNice);
            prettyPrintCert(Base64.encodeBase64String(x509Certificate.getEncoded()));
        } catch (Exception e) {
            out.println("Exception: "+e);
            return "Arghh!";
        }

        return "redirect:/certs?purchaseId="+purchaseId;
    }

    @RequestMapping(method=RequestMethod.GET, value="/myaccount")
    public String myAccount(Model model, Principal principal)
    {
        System.out.println("principal.getName:"+principal.getName());
        Purchase savedPendingPurchase = null;
        List<Purchase> confirmedPurchases = purchaseDao.findByUsersAndDateConfirm1IsNotNull(usersDao.findByUsername(principal.getName()));
        System.out.println("confirmedPurchases: "+confirmedPurchases.size());
        List<Purchase> unconfirmedPurchases = purchaseDao.findByUsersAndDateConfirm1IsNull(usersDao.findByUsername(principal.getName()));
        System.out.println("unconfirmedPurchases: "+unconfirmedPurchases.size());

        if(unconfirmedPurchases.isEmpty()) {
            Address address = MyBean.kit.wallet().freshReceiveAddress();
            Purchase newPendingPurchase = new Purchase(new Timestamp(new Date().getTime()), address.toString(), usersDao.findByUsername(principal.getName()));
            savedPendingPurchase = purchaseDao.save(newPendingPurchase);
        } else {
            savedPendingPurchase = unconfirmedPurchases.get(0);
            if(unconfirmedPurchases.size() > 1) {
                System.out.println("ERROR: there is more than one unconfirmed purchase for "+principal.getName());
            }
        }

        for (Purchase p:confirmedPurchases) {
            System.out.println("confirmed purchases: "+p);
        }

        model.addAttribute("confirmedPurchases", confirmedPurchases);
        model.addAttribute("confirmedPurchasesSize", confirmedPurchases.size());
        model.addAttribute("pendingPurchase", savedPendingPurchase==null ? null : savedPendingPurchase.getReceivingAddress());
        model.addAttribute("username", principal.getName());
        model.addAttribute("page", "myaccount");
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
                                            String password,
                                    /*@Pattern(regexp="^(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=.*\\p{Punct}).{4,10}$",
                                            message="Password must be between 4 and 10 characters long and contain a lowercase, uppercase, numeral, and punctuation character.")*/
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
            out.println("Error creating the user: " + ex.toString());
        }
        out.println("User succesfully created! (id = " + user.getUsername() + ")");

        out.println("GOTO: accountcreated");
        return "redirect:/accountcreated";
    }

    @RequestMapping(method=RequestMethod.GET, value="accountcreated")
    public String accountCreated(Model model, HttpSession session) {
        out.println("ENTERED accountcreated");
        model.addAttribute("username", session.getAttribute("username"));
        session.setAttribute("username", null);
        return "accountcreated";
    }

/*    @RequestMapping(method=RequestMethod.GET, value="/enterpayment")
    public String enterPayment(Model model, Principal principal) {
        out.println("entered EnterPayment");

        List<Purchase> purchasesPending = purchaseDao.findByUsersAndDateConfirm1IsNull(new Users(principal.getName()));
        if(purchasesPending.size() > 1) {
            System.out.println("WARNING: THERE IS MORE THAN 1 PENDING PURCHASE FOR "+principal.getName()+".");
        }

        if(purchasesPending.size() > 0) {
            model.addAttribute("pendingPurchase", purchasesPending.get(0));
            model.addAttribute("payTo", purchasesPending.get(0).getReceivingAddress());
        } else if(purchasesPending.size() == 0) {
            Address address = MyBean.kit.wallet().freshReceiveAddress();
            Purchase newPendingPurchase = new Purchase(new Timestamp(new Date().getTime()), address.toString(), usersDao.findByUsername(principal.getName()));
            Purchase savedPendingPurchase = purchaseDao.save(newPendingPurchase);
            out.println("/enterpayment, payTo: "+savedPendingPurchase.getReceivingAddress());
            model.addAttribute("payTo", savedPendingPurchase.getReceivingAddress());
        }

        return "enterpayment";
    }*/

    @RequestMapping(method=RequestMethod.GET, value="/qrcode")
    public void qrcode(Principal principal, HttpServletResponse response, HttpSession session) {

        List<Purchase> unconfirmedPurchases = purchaseDao.findByUsersAndDateConfirm1IsNull(usersDao.findByUsername(principal.getName()));
        /*if(unconfirmedPurchases.isEmpty()) {
            Address address = MyBean.kit.wallet().freshReceiveAddress();
            Purchase newPendingPurchase = new Purchase(new Timestamp(new Date().getTime()), address.toString(), usersDao.findByUsername(principal.getName()));
            savedPendingPurchase = purchaseDao.save(newPendingPurchase);
        } else {
            savedPendingPurchase = unconfirmedPurchases.get(0);
            if(unconfirmedPurchases.size() > 1) {
                System.out.println("ERROR: there is more than one unconfirmed purchase for "+principal.getName());
            }
        }*/

        String qrCodeData = "bitcoin:"+unconfirmedPurchases.get(0).getReceivingAddress()+"?amount=0.1234";
        //String charset="UTF-8"; // or "ISO-8859-1"
        int qrCodeWidth = 200;
        int qrCodeHeight = 200;
        Map<EncodeHintType, ErrorCorrectionLevel> hintMap = new HashMap<EncodeHintType, ErrorCorrectionLevel>();
        hintMap.put(EncodeHintType.ERROR_CORRECTION, ErrorCorrectionLevel.L);
        byte[] qrCodeDataBytes = qrCodeData.getBytes();

        try {
            BitMatrix matrix = new MultiFormatWriter().encode(qrCodeData, BarcodeFormat.QR_CODE, qrCodeWidth, qrCodeHeight, hintMap);
            response.setContentType("image/jpeg");
            MatrixToImageWriter.writeToStream(matrix, "jpg", response.getOutputStream());
            response.flushBuffer();
        } catch (Exception ex) {
            System.out.println("Failed to write QRcode to output stream.");
            throw new RuntimeException("IOError writing QRcode to output stream");
        }
    }

    @RequestMapping(method=RequestMethod.GET, value = "/")
    public String index(String filename, Model model) {
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
        out.println("GET /viewproducts");
        return "viewproducts";
    }

    @RequestMapping(method=RequestMethod.GET, value = "/login")
    public String login(Model model) {
        out.println("GET /login");
        return "login";
    }

    @RequestMapping(method=RequestMethod.POST, value = "/login")
    public String loginPost(String username, String password, HttpSession session, Model model) {
        out.println("POST /login");
        try {
            out.println("username: "+username+", password: "+password);
            Users user = usersDao.findByUsername(username);
            String hashedPassword = Util.getHashedPassword(password, user.getSalt());

            if ( !hashedPassword.equals(user.getPassword())) {
                out.println("invalid login");
                return "redirect:/login";
            }
            session.setAttribute("username", user.getUsername());
            out.println("/login username---->"+username);

        } catch (Exception ex) {
            SecureRandom random = new SecureRandom();
            byte slt[] = new byte[8];
            random.nextBytes(slt);
            Util.getHashedPassword(password, Base64.encodeBase64String(slt));

            out.println("User not found");
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
        out.println("captchaToken: "+captchaToken);
/*
        if (captchaToken.length() >= 7) {
            captchaToken = captchaToken.substring(0, 7).toUpperCase();
        }
*/

        //Setting the captcha token in http session
        session.setAttribute("captchaToken", captchaToken);

        response.setContentType("image/jpeg");
        try {
            OutputStream os = response.getOutputStream();
            currGcage.draw(captchaToken, os);

            response.flushBuffer();
        } catch (IOException ex) {
            out.println("Error writing captcha to output stream.");
            throw new RuntimeException("IOError writing file to output stream");
        }
    }

    // ------------------------
    // PRIVATE FIELDS
    // ------------------------

    @Autowired
    private UsersDao usersDao;

    @Autowired
    private PurchaseDao purchaseDao;

    @Autowired
    CertificateDao certificateDao;

} // class UserController
