package com.company.dev.model.app.domain;

import org.springframework.data.jpa.repository.Query;

import javax.persistence.*;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.sql.Timestamp;

@Entity
@Table(name="subscription")
public class Subscription {
    private SubscriptionPackage subscriptionPackage;
  //  private BigDecimal price;
    private Users users;
    private int id;
    private Timestamp dateCreated;

    public Subscription() {}

    public Subscription(Subscription subscription) {
        this.id = subscription.id;
        this.subscriptionPackage = subscription.subscriptionPackage;
    //    this.price = subscription.price;
        this.users = subscription.users;
    }

    public Subscription(int id) {
        this.id = id;
    }

    public Subscription(SubscriptionPackage subscriptionPackage, Users users, Timestamp dateCreated) {
        this.subscriptionPackage = subscriptionPackage;
    //    this.price = price;
        this.users = users;
        this.dateCreated = dateCreated;
    }

    @ManyToOne(fetch= FetchType.LAZY)
    @JoinColumn(name="subscription_package")
    public SubscriptionPackage getSubscriptionPackage() {
        return subscriptionPackage;
    }

    /*@Basic
    @Column(name = "subscription_package", nullable = false)
    public int getSubscriptionPackage() {
        return subscriptionPackage;
    }*/

    public void setSubscriptionPackage(SubscriptionPackage subscriptionPackage) {
        this.subscriptionPackage = subscriptionPackage;
    }

    /*@Basic
    @Column(name = "price", nullable = false, precision = 8)
    public BigDecimal getPrice() {
        return price;
    }

    public void setPrice(BigDecimal price) {
        this.price = price;
    }
*/
    @ManyToOne(fetch=FetchType.LAZY)
    @JoinColumn(name="username")
    public Users getUsers() { return users; }

    public void setUsers(Users users) { this.users = users; }


//    @SequenceGenerator(allocationSize=1, initialValue=1, sequenceName="subscription_id_seq", name="subscription_id_seq")
//    @GeneratedValue(generator="subscription_id_seq", strategy=GenerationType.SEQUENCE)
    @Id
    //@Query("SELECT public.pseudo_encrypt(nextval('subscription_id_seq'))")
    @Column(name = "id", nullable = false)
//    @Query("SELECT pseudo_encrypt(nextval('subscription_id_seq'))")
    @GeneratedValue(strategy=GenerationType.IDENTITY)
    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }

    @Basic
    @Column(name = "date_created", nullable = true)
    public Timestamp getDateCreated() {
        return dateCreated;
    }

    public void setDateCreated(Timestamp dateCreated) {
        this.dateCreated = dateCreated;
    }

}
