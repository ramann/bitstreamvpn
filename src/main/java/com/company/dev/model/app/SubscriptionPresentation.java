package com.company.dev.model.app;

import com.company.dev.model.app.domain.Subscription;

public class SubscriptionPresentation extends Subscription {
    boolean active;
    String desc;

    public SubscriptionPresentation(Subscription subscription, boolean isActive, String desc) {
        super(subscription);
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
