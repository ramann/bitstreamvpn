package com.company.dev.model.app.domain;

import javax.persistence.Basic;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Id;
import java.math.BigDecimal;
import java.sql.Timestamp;

@Entity
public class Payment {
    private int id;
    private Timestamp dateInitiated;
    private BigDecimal amount;
    private String receivingAddress;
    private Timestamp dateConfirm1;
    private Timestamp dateConfirm3;
    private Timestamp dateConfirm6;

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
    @Column(name = "amount", nullable = false, precision = 8)
    public BigDecimal getAmount() {
        return amount;
    }

    public void setAmount(BigDecimal amount) {
        this.amount = amount;
    }

    @Basic
    @Column(name = "receiving_address", nullable = false, length = 40)
    public String getReceivingAddress() {
        return receivingAddress;
    }

    public void setReceivingAddress(String receivingAddress) {
        this.receivingAddress = receivingAddress;
    }

    @Basic
    @Column(name = "date_confirm_1", nullable = true)
    public Timestamp getDateConfirm1() {
        return dateConfirm1;
    }

    public void setDateConfirm1(Timestamp dateConfirm1) {
        this.dateConfirm1 = dateConfirm1;
    }

    @Basic
    @Column(name = "date_confirm_3", nullable = true)
    public Timestamp getDateConfirm3() {
        return dateConfirm3;
    }

    public void setDateConfirm3(Timestamp dateConfirm3) {
        this.dateConfirm3 = dateConfirm3;
    }

    @Basic
    @Column(name = "date_confirm_6", nullable = true)
    public Timestamp getDateConfirm6() {
        return dateConfirm6;
    }

    public void setDateConfirm6(Timestamp dateConfirm6) {
        this.dateConfirm6 = dateConfirm6;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        Payment payment = (Payment) o;

        if (id != payment.id) return false;
        if (dateInitiated != null ? !dateInitiated.equals(payment.dateInitiated) : payment.dateInitiated != null)
            return false;
        if (amount != null ? !amount.equals(payment.amount) : payment.amount != null) return false;
        if (receivingAddress != null ? !receivingAddress.equals(payment.receivingAddress) : payment.receivingAddress != null)
            return false;
        if (dateConfirm1 != null ? !dateConfirm1.equals(payment.dateConfirm1) : payment.dateConfirm1 != null)
            return false;
        if (dateConfirm3 != null ? !dateConfirm3.equals(payment.dateConfirm3) : payment.dateConfirm3 != null)
            return false;
        if (dateConfirm6 != null ? !dateConfirm6.equals(payment.dateConfirm6) : payment.dateConfirm6 != null)
            return false;

        return true;
    }

    @Override
    public int hashCode() {
        int result = id;
        result = 31 * result + (dateInitiated != null ? dateInitiated.hashCode() : 0);
        result = 31 * result + (amount != null ? amount.hashCode() : 0);
        result = 31 * result + (receivingAddress != null ? receivingAddress.hashCode() : 0);
        result = 31 * result + (dateConfirm1 != null ? dateConfirm1.hashCode() : 0);
        result = 31 * result + (dateConfirm3 != null ? dateConfirm3.hashCode() : 0);
        result = 31 * result + (dateConfirm6 != null ? dateConfirm6.hashCode() : 0);
        return result;
    }
}
