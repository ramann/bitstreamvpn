package com.company.dev.model.app;

import com.company.dev.model.app.domain.Subscription;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SubscriptionPresentation extends Subscription {
    private final Logger logger = LoggerFactory.getLogger(this.getClass());

    boolean active;
    String desc;

    public SubscriptionPresentation(Subscription subscription, boolean isActive, String desc) {
        super(subscription);
        this.setDuration(this.getDuration()/24);
        this.active = isActive;
        this.desc = desc;
    }

    public boolean isActive() {
        return active;
    }

    public void setActive(boolean active) {
        this.active = active;
    }

    public String getDesc() {
        return desc;
    }

    public void setDesc(String desc) {
        this.desc = desc;
    }
}
