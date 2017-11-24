package com.company.dev.util;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.text.SimpleDateFormat;
import java.util.Date;

@Component
public class ScheduledTasks {


    private static final Logger log = LoggerFactory.getLogger(ScheduledTasks.class);

    private static final SimpleDateFormat dateFormat = new SimpleDateFormat("HH:mm:ss");

    @Scheduled(fixedRate = 5000)
    public void reportCurrentTime() {
        log.info("The time is now {}", dateFormat.format(new Date()));
    }

    /* connections should be disallowed if (1) the subscription is inactive, or (2) the bandwidth limit has been exceeded */
    @Scheduled(fixedRate=600000) // 10 mins
    public void removeCertificates() {}

    @Scheduled(fixedRate=600000) // 10 mins
    public void addCertificates() {}
}
