package com.company.dev.model.app;

import com.company.dev.model.app.domain.Payment;
import com.company.dev.model.app.domain.Subscription;

public class PaymentPresentation extends Payment {
    String desc;

    public PaymentPresentation(Payment payment) {
        this(payment, null);
    }

    public PaymentPresentation(Payment payment, String desc) {
        super(payment);
        this.desc = desc;
    }

    public String getDesc() {
        return desc;
    }

    public void setDesc(String desc) {
        this.desc = desc;
    }
}
