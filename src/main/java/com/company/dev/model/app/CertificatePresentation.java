package com.company.dev.model.app;

import com.company.dev.model.app.domain.Certificate;

public class CertificatePresentation extends Certificate {
    String desc;

    public CertificatePresentation(Certificate certificate, String desc) {
        super(certificate);
        this.desc = desc;
    }

    public String getDesc() {
        return desc;
    }

    public void setDesc(String desc) {
        this.desc = desc;
    }
}
