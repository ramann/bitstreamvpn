package com.company.dev.controller;

import com.company.dev.model.app.PaymentPresentation;
import com.company.dev.model.app.domain.Payment;
import com.company.dev.model.app.domain.Subscription;
import com.company.dev.model.app.domain.Users;
import com.company.dev.model.app.repo.PaymentDao;
import com.company.dev.model.app.repo.SubscriptionDao;
import com.company.dev.util.ForbiddenException;
import com.google.zxing.BarcodeFormat;
import com.google.zxing.EncodeHintType;
import com.google.zxing.MultiFormatWriter;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel;
import org.apache.coyote.http2.ConnectionException;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpStatus;
import org.springframework.http.client.support.BasicAuthorizationInterceptor;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.servlet.ModelAndView;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.math.BigDecimal;
import java.security.Principal;
import java.sql.Timestamp;
import java.util.*;

import static com.company.dev.util.Util.addDuration;
import static com.company.dev.util.Util.dateToGMT;
import static com.company.dev.util.Util.errorText;

@Controller
public class PaymentController {
    private final Logger logger = LoggerFactory.getLogger(this.getClass());

    @RequestMapping(method= RequestMethod.POST, value="/addPayment")
    public String addPayment(Model model, Principal principal, HttpSession session, int subscriptionId) {
        logger.info("/addPayment");

        Subscription subscription = subscriptionDao.findByIdAndUsers(subscriptionId, new Users(principal.getName()));
        if (subscription == null) {
            logger.error("could not find subscription for "+subscriptionId+", name:"+principal.getName());
            throw new ForbiddenException(errorText(Subscription.class.getName(), String.valueOf(subscriptionId), principal.getName()));
        }
        List<Payment> processingPayments = paymentDao
                .findBySubscriptionAndSubscription_UsersAndDateInitiatedIsNotNullAndDateConfirm1IsNullAndInErrorIsFalseOrderByDateCreatedAsc(
                    subscription,
                    new Users(principal.getName()));

        if (processingPayments.size() > 0) {
            return "processingPayments";
        }

        Date now = new Date();
        Timestamp tenMinsAgo = addDuration(new Timestamp(now.getTime()),-10, Calendar.MINUTE);
        Payment savedPendingPayment = null;

        // payments that we haven't seen, that were created within the last 10 minutes
        List<Payment> pendingPayments = paymentDao
                .findBySubscriptionAndSubscription_UsersAndDateInitiatedIsNullAndDateCreatedIsGreaterThan(
                    subscription,
                    new Users(principal.getName()),
                    tenMinsAgo);

        if(pendingPayments.isEmpty()) {
            RestTemplate restTemplate = new RestTemplate();

            HttpEntity<String> request = new HttpEntity<>("{\"method\":\"getnewaddress\"}");
            restTemplate.getInterceptors().add(
                    new BasicAuthorizationInterceptor("alice", "alicepass"));
            String newAddress = null;
            try {
                newAddress = restTemplate.postForObject("http://bitcoin:18332", request, String.class);
            } catch (Exception e) {
                logger.error("Failed to connect to wallet when trying to getnewaddress.",e);
                return ""; // TODO make a nice 500 page
            }

            String result = restTemplate.getForObject("https://blockchain.info/tobtc?currency={currency}&value={value}",
                    String.class,"USD",subscription.getPrice().toString());
            logger.debug("bitcoin price for "+subscription.getPrice().toString()+", is: "+result);
            BigDecimal amountExpecting = new BigDecimal(result);

            JSONObject getNewAddress = new JSONObject(newAddress);
            String address = getNewAddress.getString("result");

            Payment newPendingPayment = new Payment(new Timestamp(now.getTime()), address,
                    subscriptionDao.findByIdAndUsers(subscriptionId, new Users(principal.getName())), amountExpecting);
            savedPendingPayment = paymentDao.save(newPendingPayment);
        } else {
            savedPendingPayment = pendingPayments.get(0);
            if(pendingPayments.size() > 1) {
                logger.error("ERROR: there is more than one unconfirmed payment for "+principal.getName());
            }
        }

        model.addAttribute("username", principal.getName());
        model.addAttribute("paymentAmount", savedPendingPayment.getAmountExpecting());
        model.addAttribute("subscriptionId", subscriptionId);
        model.addAttribute("paymentId", savedPendingPayment.getId());
        model.addAttribute("dateCreated", dateToGMT(savedPendingPayment.getDateCreated()));
        model.addAttribute("dateDue", dateToGMT(addDuration(savedPendingPayment.getDateCreated(),10, Calendar.MINUTE)));
        model.addAttribute("pendingPayment", savedPendingPayment.getReceivingAddress());
        return "addPayment";
    }

    @RequestMapping(method=RequestMethod.GET, value="/payments")
    public String payments(Model model, Principal principal, int subscriptionId) {
        logger.info("/payments for subscriptionId: "+subscriptionId);
        Users users = new Users(principal.getName());
        Subscription subscription = subscriptionDao.findByIdAndUsers(subscriptionId, users);
        if(subscription == null) {
            throw new ForbiddenException(errorText(Subscription.class.getName(),String.valueOf(subscriptionId), principal.getName()));
        }
        Date now = new Date();
        Timestamp tenMinsAgo = addDuration(new Timestamp(now.getTime()),-10, Calendar.MINUTE);
        logger.info("ten minutes ago: "+tenMinsAgo);

        // mark payments not received on time as "in error"
        // TODO: this can be moved to a scheduled task
        /*List<Payment> paymentsNotReceivedInTime = paymentDao.findBySubscriptionAndDateInitiatedIsNullAndInErrorIsFalseAndDateCreatedIsLessThanEqual(subscription,
                tenMinsAgo);
        logger.info("paymentsNotReceivedInTime: "+paymentsNotReceivedInTime.size());
        for(Payment p: paymentsNotReceivedInTime) {
            p.setInError(true);
            paymentDao.save(p);
        }*/


        List<Payment> confirmedPayments = paymentDao.findBySubscriptionAndSubscription_UsersAndDateConfirm1IsNotNullAndInErrorIsFalseOrderByDateConfirm1Asc(
                subscription,
                users);
        List<Payment> processingPayments = paymentDao.findBySubscriptionAndSubscription_UsersAndDateInitiatedIsNotNullAndDateConfirm1IsNullAndInErrorIsFalseOrderByDateCreatedAsc(
                subscription,
                users);
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
        model.addAttribute("confirmedPaymentsSize", confirmedPayments.size());
        model.addAttribute("processingPaymentsSize", processingPayments.size());
        model.addAttribute("username",principal.getName());
        return "payments";
    }

    @RequestMapping(method=RequestMethod.GET, value="/qrcode")
    public void qrcode(Principal principal, HttpServletResponse response, int paymentId) {
        logger.info("entered /qrcode");

        Payment unconfirmedPayment = paymentDao.findByIdAndSubscription_UsersAndDateInitiatedIsNullAndInErrorIsFalse(paymentId, new Users(principal.getName()));
        if (unconfirmedPayment == null) {
            throw new ForbiddenException(errorText(Payment.class.getName(), String.valueOf(paymentId),principal.getName()));
        }
        logger.info("user for payment: "+unconfirmedPayment.getSubscription().getUsers());

        String qrCodeData = "bitcoin:"+unconfirmedPayment.getReceivingAddress()+"?amount="+ unconfirmedPayment.getAmountExpecting(); // +"?amount=0.1234";
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
