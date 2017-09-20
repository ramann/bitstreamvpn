package com.company.dev.controller;

import com.company.dev.model.app.SubscriptionPresentation;
import com.company.dev.model.app.domain.Payment;
import com.company.dev.model.app.domain.Subscription;
import com.company.dev.model.app.domain.Users;
import com.company.dev.model.app.repo.PaymentDao;
import com.company.dev.model.app.repo.SubscriptionDao;
import com.company.dev.util.TimeSpan;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.math.BigDecimal;
import java.security.Principal;
import java.sql.Timestamp;
import java.util.*;

import static com.company.dev.util.Util.*;

@Controller
public class SubscriptionController {
    private final Logger logger = LoggerFactory.getLogger(this.getClass());

    @RequestMapping(method= RequestMethod.GET, value="/addSubscription")
    public String addSubscription(Model model, Principal principal) {
        logger.info("entered /addSubscription");
        model.addAttribute("username", principal.getName());
        return "addSubscription";
    }

    @RequestMapping(method=RequestMethod.POST, value="/addSubscription")
    public String postAddSubscription(Model model, Principal principal, int duration, HttpServletResponse response) {
        if(Arrays.binarySearch(durations,duration) < 0) {
            logger.error("duration: "+duration+" is not valid");
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
        }
        Subscription subscription = new Subscription(duration, new BigDecimal(duration*pricePerUnit),
                new Users(principal.getName()), new Timestamp(new Date().getTime()));
        Subscription savedSubscription = subscriptionDao.save(subscription);
        logger.info("saved id ("+savedSubscription.getId()+"), duration is "+savedSubscription.getDuration());
        return "redirect:/myaccount";
    }

    @RequestMapping(method=RequestMethod.GET, value="/myaccount")
    public String myAccount(Model model, Principal principal, HttpSession session)
    {
        logger.info("/myaccount");

        List<Subscription> subscriptions = subscriptionDao.findByUsers(new Users(principal.getName()));
        List<SubscriptionPresentation> subscriptionPresentations = new ArrayList<SubscriptionPresentation>(subscriptions.size());
        for (Subscription s : subscriptions) {
            List<Payment> payments = paymentDao.findBySubscriptionAndSubscription_UsersAndDateConfirm1IsNotNullAndInErrorIsFalseOrderByDateConfirm1Asc(
                    s,new Users(principal.getName()));
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
            /*logger.warn("timeSpans.size:"+timeSpans.size());
            for(TimeSpan t:timeSpans) {
                logger.warn(t.toString());
            }*/

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

            SubscriptionPresentation sp = new SubscriptionPresentation(s,isActive, activeUntil);

            subscriptionPresentations.add(sp);
        }

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

    @Autowired
    SubscriptionDao subscriptionDao;

    @Autowired
    PaymentDao paymentDao;
}
