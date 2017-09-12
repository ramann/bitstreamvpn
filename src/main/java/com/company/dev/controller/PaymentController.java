package com.company.dev.controller;

import com.company.dev.model.app.PaymentPresentation;
import com.company.dev.model.app.domain.Payment;
import com.company.dev.model.app.domain.Subscription;
import com.company.dev.model.app.repo.PaymentDao;
import com.company.dev.model.app.repo.SubscriptionDao;
import com.google.zxing.BarcodeFormat;
import com.google.zxing.EncodeHintType;
import com.google.zxing.MultiFormatWriter;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpEntity;
import org.springframework.http.client.support.BasicAuthorizationInterceptor;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.client.RestTemplate;

import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.security.Principal;
import java.sql.Timestamp;
import java.util.*;

import static com.company.dev.util.Util.addDuration;
import static com.company.dev.util.Util.dateToGMT;

@Controller
public class PaymentController {
    private final Logger logger = LoggerFactory.getLogger(this.getClass());

    @RequestMapping(method= RequestMethod.POST, value="/addPayment")
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
            RestTemplate restTemplate = new RestTemplate();

            String bitcoinUrl = "http://" + "alice" + ":" + "alicepass" + "@" + "127.0.0.1" + ":" + "19332";
            HttpEntity<String> request = new HttpEntity<>("{\"method\":\"getnewaddress\"}");
            restTemplate.getInterceptors().add(
                    new BasicAuthorizationInterceptor("alice", "alicepass"));
            /*restTemplate.exchange(
                    "http://localhost:8080/spring-security-rest-template/api/foos/1",
                    HttpMethod.POST, null, String.class);*/
            String foo = restTemplate.postForObject("http://127.0.0.1:19332", request, String.class);
            JSONObject getNewAddress = new JSONObject(foo);
            String address = getNewAddress.getString("result");

            //Address address = MyBean.kit.wallet().freshReceiveAddress();
            Payment newPendingPayment = new Payment(new Timestamp(now.getTime()), address,
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
        // TODO: this can be moved to a scheduled task
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

    @Autowired
    PaymentDao paymentDao;

    @Autowired
    SubscriptionDao subscriptionDao;
}
