package com.company.dev.model.app.domain;

import javax.persistence.*;
import java.sql.Time;
import java.sql.Timestamp;

@Entity
@Table(name="certificate")
public class Certificate {
    private int id;
    private Timestamp dateInitiated;
    private String csrText;
    private boolean signed;
    private String certText;
    private Boolean revoked;
    private Long serial;
    private Subscription subscription;
    private Timestamp dateCreated;
    private String subject;

    public Certificate() {}

    public Certificate(String subject, Subscription subscription) {
        this.subject = subject;
        this.subscription = subscription;
    }

    public Certificate(Certificate c) {  // clone?
        this.id = c.getId();
        this.dateInitiated = this.getDateInitiated();
        this.csrText = this.getCsrText();
        this.signed = this.isSigned();
        this.certText = this.getCertText();
        this.revoked = this.getRevoked();
        this.serial = this.getSerial();
        this.subscription = this.getSubscription();
        this.dateCreated = this.getDateCreated();
        this.subject = this.getSubject();
    }

    public Certificate(Timestamp dateCreated, String csrText, boolean signed, Subscription subscription, Long serial) {
        this.dateCreated = dateCreated;
        this.csrText = csrText;
        this.signed = signed;
        this.subscription = subscription;
        this.serial = serial;
    }

    @ManyToOne(fetch=FetchType.LAZY)
    @JoinColumn(name="subscription")
    public Subscription getSubscription() {
        return subscription;
    }

    public void setSubscription(Subscription subscription) {
        this.subscription = subscription;
    }

    @Id
    @GeneratedValue(strategy=GenerationType.IDENTITY)
    @Column(name="id")
    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }

    @Basic
    @Column(name = "date_initiated", nullable = false)
    public Timestamp getDateInitiated() {
        return dateInitiated;
    }

    public void setDateInitiated(Timestamp dateInitiated) {
        this.dateInitiated = dateInitiated;
    }

    @Basic
    @Column(name = "date_created", nullable = false)
    public Timestamp getDateCreated() {
        return dateCreated;
    }

    public void setDateCreated(Timestamp dateCreated) {
        this.dateCreated = dateCreated;
    }


    @Basic
    @Column(name = "csr_text", nullable = false, length = 4096)
    public String getCsrText() {
        return csrText;
    }

    public void setCsrText(String csrText) {
        this.csrText = csrText;
    }

    @Basic
    @Column(name = "signed", nullable = false)
    public boolean isSigned() {
        return signed;
    }

    public void setSigned(boolean signed) {
        this.signed = signed;
    }

    @Basic
    @Column(name = "cert_text", nullable = true, length = 4096)
    public String getCertText() {
        return certText;
    }

    public void setCertText(String certText) {
        this.certText = certText;
    }

    @Basic
    @Column(name = "subject", nullable = true, length = 100)
    public String getSubject() {
        return subject;
    }

    public void setSubject(String subject) {
        this.subject = subject;
    }


    @Basic
    @Column(name = "revoked", nullable = true)
    public Boolean getRevoked() {
        return revoked;
    }

    public void setRevoked(Boolean revoked) {
        this.revoked = revoked;
    }

    @Basic
    @Column(name = "serial", nullable = true)
    public Long getSerial() {
        return serial;
    }

    public void setSerial(Long serial) {
        this.serial = serial;
    } // TODO regenerate the .equals methods because we've added this column after

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        Certificate that = (Certificate) o;

        if (id != that.id) return false;
        if (signed != that.signed) return false;
        if (dateInitiated != null ? !dateInitiated.equals(that.dateInitiated) : that.dateInitiated != null)
            return false;
        if (csrText != null ? !csrText.equals(that.csrText) : that.csrText != null) return false;
        if (certText != null ? !certText.equals(that.certText) : that.certText != null) return false;
        if (revoked != null ? !revoked.equals(that.revoked) : that.revoked != null) return false;

        return true;
    }

    @Override
    public int hashCode() {
        int result = id;
        result = 31 * result + (dateInitiated != null ? dateInitiated.hashCode() : 0);
        result = 31 * result + (csrText != null ? csrText.hashCode() : 0);
        result = 31 * result + (signed ? 1 : 0);
        result = 31 * result + (certText != null ? certText.hashCode() : 0);
        result = 31 * result + (revoked != null ? revoked.hashCode() : 0);
        return result;
    }
}
