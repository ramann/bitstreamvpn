package com.company.dev.model.ipsec.domain;

import javax.persistence.*;

@Entity
@Table(name = "certificate_authorities", schema = "testipsecdb", catalog = "")
public class CertificateAuthorities {
    private int id;
    private int certificate;

    public CertificateAuthorities() {}

    public CertificateAuthorities(int certificate) {
        this.certificate = certificate;
    }

    @Id
    @Column(name = "id", nullable = false)
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }

    @Basic
    @Column(name = "certificate", nullable = false)
    public int getCertificate() {
        return certificate;
    }

    public void setCertificate(int certificate) {
        this.certificate = certificate;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        CertificateAuthorities that = (CertificateAuthorities) o;

        if (id != that.id) return false;
        if (certificate != that.certificate) return false;

        return true;
    }

    @Override
    public int hashCode() {
        int result = id;
        result = 31 * result + certificate;
        return result;
    }
}
