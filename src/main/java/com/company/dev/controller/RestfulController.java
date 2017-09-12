package com.company.dev.controller;

import com.company.dev.model.app.domain.Payment;
import com.company.dev.model.app.repo.PaymentDao;
import com.company.dev.model.app.repo.SubscriptionDao;
import org.json.JSONArray;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import java.math.BigDecimal;
import java.sql.Timestamp;
import java.util.Calendar;
import java.util.Date;

import static com.company.dev.util.Util.addDuration;

@RestController
public class RestfulController {
    private final Logger logger = LoggerFactory.getLogger(this.getClass());

    @Autowired
    private PaymentDao paymentDao;

    @Autowired
    private SubscriptionDao subscriptionDao;

    @RequestMapping(method=RequestMethod.POST, value="/updateConfirmations")
    public void updateConfirmations(String json) {
        JSONArray receivedByAddress = new JSONArray(json);

        //JSONArray txs = txSinceBlock.getJSONArray("transactions");

        for (int i=0; i<receivedByAddress.length(); i++) {
            JSONObject r = receivedByAddress.getJSONObject(i);
            String address = r.getString("address");
            double amount = r.getDouble("amount");
            int confirmations = r.getInt("confirmations");

            Payment payment = paymentDao.findByReceivingAddress(address);
            if (payment != null && payment.getDateConfirm6()==null) {
                logger.info("found payment for "+payment.getReceivingAddress());
                logger.info("amount: "+amount);
                logger.info("confirmations: "+confirmations);
                BigDecimal amountExpecting = subscriptionDao.findById(payment.getSubscription().getId()).getPrice();
                BigDecimal amountConfirmed = new BigDecimal(amount);

                payment.setInError(amountConfirmed.compareTo(amountExpecting) < 0);

                if (confirmations >= 1 && payment.getDateConfirm1()==null) {
                    payment.setDateConfirm1(new Timestamp(new Date().getTime()));
                    logger.info("updateConfirmations setDateConfirm1: "+payment.getDateConfirm1());
                }
                if (confirmations >= 3 && payment.getDateConfirm3()==null) {
                    payment.setDateConfirm3(new Timestamp(new Date().getTime()));
                    logger.info("updateConfirmations setDateConfirm3: "+payment.getDateConfirm3());
                }
                if (confirmations >= 6 && payment.getDateConfirm6()==null) {
                    payment.setDateConfirm6(new Timestamp(new Date().getTime()));
                    logger.info("updateConfirmations setDateConfirm6: "+payment.getDateConfirm6());
                }
            }
        }
    }

    @RequestMapping(method = RequestMethod.POST, value = "/updatePayment")
    public void updatePayment(String address, BigDecimal amount, long timeSecs, int confirmations, String transaction) {
        if(amount.doubleValue()<=0.0) {
            return;
        }
        Payment payment = paymentDao.findByReceivingAddress(address);
        if(payment == null) {
            return;
        }
        logger.info("PING RECEIVED!\n" +
                " address: " + address+"\n" +
                " amount: " + amount+"\n" +
                " time: " + timeSecs+"\n" +
                " confirmations: "+confirmations+"\n" +
                " transaction: "+transaction+"\n" +
                "  PAYMENT RECORD:"+payment.toString());

        BigDecimal amountExpecting = subscriptionDao.findById(payment.getSubscription().getId()).getPrice();
        BigDecimal amountReceived = amount;
        Date timeReceived = new Date(timeSecs*1000);

        /**
         * -walletnotify will alert on 0 or 1 confirmations.
         * -reindex will give us the current number of confirmations, and (oddly) the time of the 1st confirmation
         */
        if(confirmations >= 0 && payment.getDateInitiated()==null) {
            payment.setDateInitiated(new Timestamp(timeReceived.getTime()));
            logger.info("setDateInitiated: "+payment.getDateInitiated());
        }
        if (confirmations >= 1 && payment.getDateConfirm1()==null) {
            payment.setDateConfirm1(new Timestamp(new Date().getTime()));
            logger.info("setDateConfirm1: "+payment.getDateConfirm1());
        }
        if (confirmations >= 3 && payment.getDateConfirm3()==null) {
            payment.setDateConfirm3(new Timestamp(new Date().getTime()));
            logger.info("setDateConfirm3: "+payment.getDateConfirm3());
        }
        if (confirmations >= 6 && payment.getDateConfirm6()==null) {
            payment.setDateConfirm6(new Timestamp(new Date().getTime()));
            logger.info("setDateConfirm6: "+payment.getDateConfirm6());
        }
        // if the payment is first seen more than 10 mins after the payment was created, mark the payment as "in error"
        // due to the volatility of bitcoin exchange rates, they will need to pay again
        if (payment.getDateConfirm1() == null &&
                payment.getDateConfirm3() == null &&
                payment.getDateConfirm6() == null &&
                payment.getDateInitiated().after(addDuration(payment.getDateCreated(),10, Calendar.MINUTE)))
        {
            logger.error("marking payment in error");
            payment.setInError(true);
        }

        // if the amount received at this address is not the same as the amount we were expecting, mark it "in error"
        payment.setInError(!amountReceived.equals(amountExpecting));

        payment.setAmount(amountReceived);
        paymentDao.save(payment);

    }
}
