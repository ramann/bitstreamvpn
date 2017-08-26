package com.company.dev.model;

import javax.persistence.*;
import java.sql.Timestamp;

@Entity
public class Certificate {
    private int id;
    private Timestamp dateInitiated;
    private String csrText;
    private boolean signed;
    private String certText;
    private Boolean revoked;
    private Purchase purchase;
    private Long serial;


    public Certificate() {}

    public Certificate(Timestamp dateInitiated, String csrText, boolean signed, Purchase purchase, Long serial) {
        this.dateInitiated = dateInitiated;
        this.csrText = csrText;
        this.signed = signed;
        this.purchase = purchase;
        this.serial = serial;
    }

    @ManyToOne(fetch=FetchType.LAZY)
    @JoinColumn(name="purchase_id")
    public Purchase getPurchase() { return purchase; }

    public void setPurchase(Purchase purchase) { this.purchase = purchase; }

    @SequenceGenerator(allocationSize=1, initialValue=1, sequenceName="certificate_id_seq", name="certificate_id_seq")
    @GeneratedValue(generator="certificate_id_seq", strategy=GenerationType.SEQUENCE)
    @Id
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
