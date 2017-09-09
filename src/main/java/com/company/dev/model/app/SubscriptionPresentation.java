package com.company.dev.model.app;

import com.company.dev.model.app.domain.Subscription;

public class SubscriptionPresentation extends Subscription {
    boolean isActive;

    public SubscriptionPresentation(Subscription subscription) {
        super(subscription);
    }

    public boolean isActive() {
        return isActive;
    }

    public void setActive(boolean active) {
        isActive = active;
    }
}
