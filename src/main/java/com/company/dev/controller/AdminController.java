package com.company.dev.controller;

import com.company.dev.model.app.SubscriptionPresentation;
import com.company.dev.model.app.domain.*;
import com.company.dev.model.app.repo.*;
import com.company.dev.model.ipsec.domain.*;
import com.company.dev.model.ipsec.repo.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.math.BigInteger;
import java.security.Principal;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import static com.company.dev.util.Util.dateToGMT;

@Controller
public class AdminController {

    private final Logger logger = LoggerFactory.getLogger(this.getClass());

    @RequestMapping(method= RequestMethod.GET, value="/showDB")
    public String addSubscription(Model model, Principal principal) {
        logger.info("entered /showDB");
        List<Identities> identities = identitiesDao.findAll();
        List<Certificates> certificates = certificatesDao.findAll();
        List<CertificateIdentity> certificateIdentities = certificateIdentityDao.findAll();
        List<IkeConfigs> ikeConfigs = ikeConfigsDao.findAll();
        List<PeerConfigs> peerConfigs = peerConfigsDao.findAll();
        List<ChildConfigs> childConfigs = childConfigsDao.findAll();
        List<PeerConfigChildConfig> peerConfigChildConfigs = peerConfigChildConfigDao.findAll();
        List<TrafficSelectors> trafficSelectors = trafficSelectorsDao.findAll();
        List<ChildConfigTrafficSelector> childConfigTrafficSelectors = childConfigTrafficSelectorDao.findAll();

        List<Addresses> addresses = addressesDao.findAll();
        List<CertificateAuthorities> certificateAuthorities = certificateAuthoritiesDao.findAll();
        List<Connections> connections = connectionsDao.findAll();
        List<Pools> pools = poolsDao.findAll();
        List<PrivateKeyIdentity> privateKeyIdentities = privateKeyIdentityDao.findAll();
        List<PrivateKeys> privateKeys = privateKeysDao.findAll();

        model.addAttribute("identities", identities);
        model.addAttribute("certificates", certificates);
        model.addAttribute("certificateIdentities", certificateIdentities);
        model.addAttribute("ikeConfigs", ikeConfigs);
        model.addAttribute("peerConfigs", peerConfigs);
        model.addAttribute("childConfigs", childConfigs);
        model.addAttribute("peerConfigChildConfigs", peerConfigChildConfigs);
        model.addAttribute("trafficSelectors", trafficSelectors);
        model.addAttribute("childConfigTrafficSelectors", childConfigTrafficSelectors);

        model.addAttribute("addresses", addresses);
        model.addAttribute("certificateAuthorities", certificateAuthorities);
        model.addAttribute("connections",connections);
        model.addAttribute("pools", pools);
        model.addAttribute("privateKeyIdentities", privateKeyIdentities);
        model.addAttribute("privateKeys", privateKeys);

        List<String> usernames = new ArrayList<String>();
        for (Users u : usersDao.findAll()) {
            usernames.add(u.getUsername());
        }
        List<Subscription> subscriptions = subscriptionDao.findAll();
        List<Certificate> certificateList = certificateDao.findAll();
        List<Payment> payments = paymentDao.findAll();

        model.addAttribute("usernames", usernames);
        model.addAttribute("subscriptions", subscriptions);
        model.addAttribute("certificateList", certificateList);
        model.addAttribute("payments", payments);

        return "showDB";
    }

/*    @RequestMapping(method=RequestMethod.POST, value="/addSubscription")
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
        *//**
         * certAdded and certDeleted should really never be false - only null or true
         *//*
        model.addAttribute("certAdded",(session.getAttribute("certAdded")!=null) ? session.getAttribute("certAdded") : false);
        model.addAttribute("certDeleted",(session.getAttribute("certDeleted")!=null) ? session.getAttribute("certDeleted") : false);

*//*        model.addAttribute("certificates", certificates);
        model.addAttribute("certificatesSize",certificates.size());
        *//*
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
    SubscriptionPackageDao subscriptionPackageDao;*/

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
    AddressesDao addressesDao;

    @Autowired
    CertificateAuthoritiesDao certificateAuthoritiesDao;

    @Autowired
    ConnectionsDao connectionsDao;

    @Autowired
    PoolsDao poolsDao;

    @Autowired
    PrivateKeyIdentityDao privateKeyIdentityDao;

    @Autowired
    PrivateKeysDao privateKeysDao;

    @Autowired
    UsersDao usersDao;

    @Autowired
    SubscriptionDao subscriptionDao;

    @Autowired
    CertificateDao certificateDao;

    @Autowired
    PaymentDao paymentDao;
}
