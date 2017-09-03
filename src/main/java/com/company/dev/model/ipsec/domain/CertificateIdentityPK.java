package com.company.dev.model.ipsec.domain;

import javax.persistence.Column;
import javax.persistence.Id;
import java.io.Serializable;

public class CertificateIdentityPK implements Serializable {
    private int certificate;
    private int identity;

    @Column(name = "certificate", nullable = false)
    @Id
    public int getCertificate() {
        return certificate;
    }

    public void setCertificate(int certificate) {
        this.certificate = certificate;
    }

    @Column(name = "identity", nullable = false)
    @Id
    public int getIdentity() {
        return identity;
    }

    public void setIdentity(int identity) {
        this.identity = identity;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        CertificateIdentityPK that = (CertificateIdentityPK) o;

        if (certificate != that.certificate) return false;
        if (identity != that.identity) return false;

        return true;
    }

    @Override
    public int hashCode() {
        int result = certificate;
        result = 31 * result + identity;
        return result;
    }
}
