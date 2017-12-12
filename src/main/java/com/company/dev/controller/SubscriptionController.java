package com.company.dev.controller;

import com.company.dev.model.app.SubscriptionPresentation;
import com.company.dev.model.app.domain.Payment;
import com.company.dev.model.app.domain.Subscription;
import com.company.dev.model.app.domain.SubscriptionPackage;
import com.company.dev.model.app.domain.Users;
import com.company.dev.model.app.repo.PaymentDao;
import com.company.dev.model.app.repo.SubscriptionDao;
import com.company.dev.model.app.repo.SubscriptionPackageDao;
import com.company.dev.util.TimeSpan;
import com.company.dev.util.Util;
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
import java.math.BigInteger;
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
        List<SubscriptionPackage> subscriptionPackages = subscriptionPackageDao.findAll();
        for (SubscriptionPackage sp: subscriptionPackages) {
            sp.setBytes(sp.getBytes().divide(new BigInteger("1000").pow(3))); //TODO: Can we do this with thymeleaf?
        }
        model.addAttribute("subscriptionPackages", subscriptionPackages);
        model.addAttribute("username", principal.getName());
        return "addSubscription";
    }

    @RequestMapping(method=RequestMethod.POST, value="/addSubscription")
    public String postAddSubscription(Model model, Principal principal, int subscriptionPackage, HttpServletResponse response) {
        SubscriptionPackage subPackage = subscriptionPackageDao.findById(subscriptionPackage);

        if(subPackage == null) {
            logger.error("subscriptionPackage: "+subscriptionPackage+" is not valid");
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
        }
        Subscription subscription = new Subscription(subPackage,
                new Users(principal.getName()), new Timestamp(new Date().getTime()));
        Subscription savedSubscription = subscriptionDao.save(subscription);

        return "redirect:/payments?subscriptionId="+savedSubscription.getId(); //"redirect:/myaccount";
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

            boolean isCurrent = false;
            String statusMessage = "";
            for (int i=payments.size()-1; i>=0 && !isCurrent; i--) {
                Date now = new Date();
                if (now.before(payments.get(i).getDateEnd())) {
                    isCurrent = true;
                    if(payments.get(i).getBandwidth().compareTo(s.getSubscriptionPackage().getBytes()) >= 0) {
                        statusMessage = "inactive (due to high bandwidth usage)";
                    } else {
                        statusMessage = "active (until " + dateToGMT(payments.get(i).getDateEnd()) + ")";
                    }
                    logger.warn(statusMessage);
                }
            }

            SubscriptionPresentation sp = new SubscriptionPresentation(s,isCurrent, statusMessage);

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

    @Autowired
    SubscriptionPackageDao subscriptionPackageDao;
}
