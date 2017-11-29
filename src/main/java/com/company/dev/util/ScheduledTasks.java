package com.company.dev.util;

import com.company.dev.model.app.SubscriptionPresentation;
import com.company.dev.model.app.domain.Payment;
import com.company.dev.model.app.domain.Subscription;
import com.company.dev.model.app.domain.SubscriptionPackage;
import com.company.dev.model.app.domain.Users;
import com.company.dev.model.app.repo.PaymentDao;
import com.company.dev.model.app.repo.SubscriptionDao;
import org.hibernate.Hibernate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;

import static com.company.dev.util.Util.dateToGMT;

@Component
public class ScheduledTasks {


    private static final Logger logger = LoggerFactory.getLogger(ScheduledTasks.class);

    private static final SimpleDateFormat dateFormat = new SimpleDateFormat("HH:mm:ss");

    @Scheduled(fixedRate = 60000)
    public void reportCurrentTime() {
        logger.info("The time is now {}", dateFormat.format(new Date()));
    }

    /* connections should be disallowed if (1) the subscription is inactive, or (2) the bandwidth limit has been exceeded */
    @Scheduled(fixedRate=300000) // 5 mins
    public void removeCertificates() {
        logger.info("entered removeCertificates");
        Iterable<Subscription> subscriptions = subscriptionDao.findAll();

        for (Subscription s : subscriptions) {
            List<Payment> payments = paymentDao.findBySubscriptionAndDateConfirm1IsNotNullAndInErrorIsFalseOrderByDateConfirm1Asc(s);

            boolean isActive = false;
            for (int i=payments.size()-1; i>=0 && !isActive; i--) {
                Date now = new Date();
                if (now.before(payments.get(i).getDateEnd())) {
                    isActive = true;
                    logger.info("found active payment: "+payments.get(i).getId());

                    SubscriptionPackage sp = s.getSubscriptionPackage();

                    // if the payment is active
                    // and the bandwidth used is >= the subscription package's bandwidth
                    if (payments.get(i).getBandwidth().compareTo(sp.getBytes()) >= 0) {
                        logger.info("payment's bandwidth "+payments.get(i).getBandwidth()+" is too high");
                        certHelper.removeCertsIpsec(s);
                    } else {
                        logger.info("payment's bandwidth "+payments.get(i).getBandwidth()+" is NOT too high");
                    }
                }
            }

            if ( !isActive ) {
                logger.info("subscription is not active");
                certHelper.removeCertsIpsec(s);
            }
        }
    }

    @Autowired
    SubscriptionDao subscriptionDao;

    @Autowired
    PaymentDao paymentDao;

    @Autowired
    CertHelper certHelper;
}
