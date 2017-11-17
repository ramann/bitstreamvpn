package com.company.dev.model.app.domain;

//import org.springframework.data.annotation.Id;
import org.springframework.data.jpa.repository.Query;

import javax.persistence.*;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.sql.Timestamp;

@Entity
@Table(name="payment")
public class Payment {
    private int id;
    private Timestamp dateInitiated;
    private BigDecimal amount;
    private BigDecimal amountExpecting;
    private String receivingAddress;
    private Timestamp dateConfirm1;
    private Timestamp dateConfirm3;
    private Timestamp dateConfirm6;
    private Subscription subscription;
    private boolean inError = false;
    private Timestamp dateCreated;
    private Timestamp dateStart;
    private Timestamp dateEnd;
    private BigInteger bandwidth = BigInteger.ZERO;


    public Payment() {
    }

    public Payment(Payment payment) {
        this.id = payment.getId();
        this.dateInitiated = payment.getDateInitiated();
        this.amount = payment.getAmount();
        this.receivingAddress = payment.getReceivingAddress();
        this.dateConfirm1 = payment.getDateConfirm1();
        this.dateConfirm3 = payment.getDateConfirm3();
        this.dateConfirm6 = payment.getDateConfirm6();
        this.subscription = payment.getSubscription();
        this.bandwidth = payment.getBandwidth();
        this.inError = payment.isInError();
    }

    public Payment(Timestamp dateCreated, String receivingAddress, Subscription subscription, BigDecimal amountExpecting) {
        this.dateCreated = dateCreated;
        //    this.amount = amount;
        this.receivingAddress = receivingAddress;
        //this.users = users;
        this.subscription = subscription;
        this.amountExpecting = amountExpecting;
    }

    /*

    @ManyToOne(fetch=FetchType.LAZY)
    @JoinColumn(name="username")
    public Users getUsers() { return users; }

    public void setUsers(Users users) { this.users = users; }
*/

    @Id
   // @SequenceGenerator(allocationSize=1, initialValue=1, sequenceName="payment_id_seq", name="payment_id_seq")
   // @GeneratedValue(generator="payment_id_seq", strategy=GenerationType.SEQUENCE)
    @GeneratedValue(strategy=GenerationType.IDENTITY)
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
    @Column(name = "amount", nullable = true, precision = 8)
    public BigDecimal getAmount() {
        return amount;
    }

    public void setAmount(BigDecimal amount) {
        this.amount = amount;
    }

    @Basic
    @Column(name = "amount_expecting", nullable = false, precision = 8)
    public BigDecimal getAmountExpecting() {
        return amountExpecting;
    }

    public void setAmountExpecting(BigDecimal amountExpecting) {
        this.amountExpecting = amountExpecting;
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

    @Basic
    @Column(name = "in_error", nullable = false)
    public boolean isInError() { return inError; }

    public void setInError(boolean inError) {
        this.inError = inError;
    }

    @Basic
    @Column(name = "date_created", nullable = true)
    public Timestamp getDateCreated() {
        return dateCreated;
    }

    public void setDateCreated(Timestamp dateCreated) {
        this.dateCreated = dateCreated;
    }

    @Basic
    @Column(name = "date_start", nullable = true)
    public Timestamp getDateStart() {
        return dateStart;
    }

    public void setDateStart(Timestamp dateStart) {
        this.dateStart = dateStart;
    }

    @Basic
    @Column(name = "date_end", nullable = true)
    public Timestamp getDateEnd() {
        return dateEnd;
    }

    public void setDateEnd(Timestamp dateEnd) {
        this.dateEnd = dateEnd;
    }

    @Basic
    @Column(name = "bandwidth", nullable = false)
    public BigInteger getBandwidth() {
        return bandwidth;
    }

    public void setBandwidth(BigInteger bandwidth) {
        this.bandwidth = bandwidth;
    }

    @ManyToOne(fetch= FetchType.LAZY)
    @JoinColumn(name="subscription")
    public Subscription getSubscription() {
        return subscription;
    }

    public void setSubscription(Subscription subscription) {
        this.subscription = subscription;
    }

    @Override
    public String toString() {
        return "Payment{" +
                "id=" + id +
                ", dateInitiated=" + dateInitiated +
                ", amount=" + amount +
                ", amountExpecting=" + amountExpecting +
                ", receivingAddress='" + receivingAddress + '\'' +
                ", dateConfirm1=" + dateConfirm1 +
                ", dateConfirm3=" + dateConfirm3 +
                ", dateConfirm6=" + dateConfirm6 +
                ", subscription=" + subscription.getId() +
                ", inError=" + inError +
                ", dateCreated=" + dateCreated +
                '}';
    }
}
