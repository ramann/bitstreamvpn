package com.company.dev.model.ipsec.domain;

import javax.persistence.*;

@Entity
@Table(name = "certificate_identity", schema = "testipsecdb", catalog = "")
@IdClass(CertificateIdentityPK.class)
public class CertificateIdentity {
    private int certificate;
    private int identity;

    public CertificateIdentity() {}

    public CertificateIdentity(int certificate, int identity) {
        this.certificate = certificate;
        this.identity = identity;
    }

    @Id
    @Column(name = "certificate", nullable = false)
    public int getCertificate() {
        return certificate;
    }

    public void setCertificate(int certificate) {
        this.certificate = certificate;
    }

    @Id
    @Column(name = "identity", nullable = false)
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

        CertificateIdentity that = (CertificateIdentity) o;

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
