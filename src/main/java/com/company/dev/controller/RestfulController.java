package com.company.dev.controller;

import com.company.dev.model.app.domain.Payment;
import com.company.dev.model.app.domain.Subscription;
import com.company.dev.model.app.repo.PaymentDao;
import com.company.dev.model.app.repo.SubscriptionDao;
import com.company.dev.util.TimeSpan;
import org.json.JSONArray;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import java.math.BigDecimal;
import java.math.RoundingMode;
import java.security.Principal;
import java.sql.Timestamp;
import java.util.Calendar;
import java.util.Date;
import java.util.List;

import static com.company.dev.util.Util.addDuration;

@RestController
public class RestfulController {
    private final Logger logger = LoggerFactory.getLogger(this.getClass());

    @Autowired
    private PaymentDao paymentDao;

    public void setStartAndEndDates(Subscription subscription) {
        List<Payment> payments = paymentDao.findBySubscriptionAndDateConfirm1IsNotNullAndInErrorIsFalseOrderByDateConfirm1Asc(subscription);

        for(int i=0; i<payments.size(); i++) {
            if (payments.get(i).getDateStart() == null || payments.get(i).getDateEnd() == null) {
                Timestamp thisDateConfirm1 = payments.get(i).getDateConfirm1();
                Timestamp thisDateConfirm1PlusDuration = addDuration(thisDateConfirm1, subscription.getSubscriptionPackage().getDuration(), Calendar.DAY_OF_MONTH);

                if (i == 0) { // if this is the first payment
                    if (payments.get(i).getDateStart() == null)
                        payments.get(i).setDateStart(thisDateConfirm1);

                    if (payments.get(i).getDateEnd() == null)
                        payments.get(i).setDateEnd(thisDateConfirm1PlusDuration);
                } else {
                    if (thisDateConfirm1.before(payments.get(i - 1).getDateEnd())) {
                        Timestamp begin = payments.get(i - 1).getDateEnd();
                        Timestamp end = addDuration(payments.get(i - 1).getDateEnd(), subscription.getSubscriptionPackage().getDuration(), Calendar.DAY_OF_MONTH);

                        if (payments.get(i).getDateStart() == null)
                            payments.get(i).setDateStart(begin);

                        if (payments.get(i).getDateEnd() == null)
                            payments.get(i).setDateEnd(end);
                        //timeSpans.add(new TimeSpan(begin, end));
                    } else {
                        if (payments.get(i).getDateStart() == null)
                            payments.get(i).setDateStart(thisDateConfirm1);

                        if (payments.get(i).getDateEnd() == null)
                            payments.get(i).setDateEnd(thisDateConfirm1PlusDuration);
                        //timeSpans.add(new TimeSpan(thisDateConfirm1, thisDateConfirm1PlusDuration));
                    }
                }
            }
        }
    }

    @RequestMapping(method=RequestMethod.POST, value="/updateConfirmations")
    public void updateConfirmations(Principal principal, String json) {
        if (!principal.getName().equals("apiuser")) {
            logger.error("call to /updateConfirmations by "+principal.getName());
            return;
        }
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
                BigDecimal amountExpecting = payment.getAmountExpecting();
                BigDecimal amountConfirmed = new BigDecimal(amount).setScale(8,RoundingMode.HALF_UP);

                logger.info("amountConfirmed: "+amountConfirmed);
                logger.info("amountExpecting: "+amountExpecting);
                logger.info("amountConfirmed.compareTo(amountExpecting): "+amountConfirmed.compareTo(amountExpecting));

                /**
                 * Instead of 0.00037325, double 3.7325E-4 gets constructed as a BigDecimal with a value like
                 * 0.000373249999999999992374155599605956012965179979801177978515625, which is less than
                 * 0.00037325, which would result in this payment being "in error".
                 * To address this, we set the scale for when assigning amountConfirmed above.
                 */
                payment.setInError(amountConfirmed.compareTo(amountExpecting) < 0);

                if (confirmations >= 0) {
                    if (payment.getDateInitiated() == null) {
                        payment.setDateInitiated(new Timestamp(new Date().getTime()));
                        logger.info("update dateInitiated: "+payment.getDateInitiated());
                    }
                    if (payment.getAmount() == null) {
                        payment.setAmount(amountConfirmed);
                        logger.info("update payment Amount: "+payment.getAmount());
                    }
                }

                if (confirmations >= 1 && payment.getDateConfirm1()==null) {
                    payment.setDateConfirm1(new Timestamp(new Date().getTime()));
                    setStartAndEndDates(payment.getSubscription());
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
                paymentDao.save(payment);
            }
        }
    }


    /**
     * -walletnotify will alert on 0 or 1 confirmations.
     * -reindex will give us the current number of confirmations, and (oddly) the time of the 1st confirmation
     */
    @RequestMapping(method = RequestMethod.POST, value = "/updatePayment")
    public void updatePayment(Principal principal, String address, BigDecimal amount, long timeSecs, int confirmations, String transaction) {
        if (!principal.getName().equals("apiuser")) {
            logger.error("call to /updatePayment by "+principal.getName());
            return;
        }

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

        BigDecimal amountExpecting = payment.getAmountExpecting();
        BigDecimal amountReceived = amount;
        Date timeReceived = new Date(timeSecs*1000);

        if(confirmations >= 0) {
            if(payment.getAmount() == null ) {
                payment.setAmount(amountReceived);
                logger.info("setAmount: "+payment.getAmount());
            }
            if(payment.getDateInitiated()==null) {
                payment.setDateInitiated(new Timestamp(timeReceived.getTime()));
                logger.info("setDateInitiated: " + payment.getDateInitiated());
            }
        }
        if (confirmations >= 1 && payment.getDateConfirm1()==null) {
            payment.setDateConfirm1(new Timestamp(new Date().getTime()));
            setStartAndEndDates(payment.getSubscription());
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
        logger.info("amountReceived: "+amountReceived);
        logger.info("amountExpecting: "+amountExpecting);
        logger.info("amountReceived.compareTo(amountExpecting): "+amountReceived.compareTo(amountExpecting));
        payment.setInError(amountReceived.compareTo(amountExpecting) < 0);

        payment.setAmount(amountReceived);
        paymentDao.save(payment);

    }


    @RequestMapping(method = RequestMethod.POST, value="/updateBandwidth")
    public void updateBandwidth(Principal principal, String id, BigDecimal totalBytes) {

    }
}
