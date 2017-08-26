package com.company.dev;

import javax.persistence.Basic;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Id;
import java.sql.Timestamp;

@Entity
public class Certificate {
    private int id;
    private Timestamp dateInitiated;
    private String csrText;
    private boolean signed;
    private String certText;
    private Boolean revoked;
    private Long serial;

    @Id
    @Column(name = "id", nullable = false)
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
    }

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
        if (serial != null ? !serial.equals(that.serial) : that.serial != null) return false;

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
        result = 31 * result + (serial != null ? serial.hashCode() : 0);
        return result;
    }
}
