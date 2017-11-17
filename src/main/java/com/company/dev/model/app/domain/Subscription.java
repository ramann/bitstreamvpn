package com.company.dev.model.app.domain;

import org.springframework.data.jpa.repository.Query;

import javax.persistence.*;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.sql.Timestamp;

@Entity
@Table(name="subscription")
public class Subscription {
    private int duration;
    private BigDecimal price;
    private Users users;
    private int id;
    private Timestamp dateCreated;

    public Subscription() {}

    public Subscription(Subscription subscription) {
        this.id = subscription.id;
        this.duration = subscription.duration;
        this.price = subscription.price;
        this.users = subscription.users;
    }

    public Subscription(int id) {
        this.id = id;
    }

    public Subscription(int duration, BigDecimal price, Users users, Timestamp dateCreated) {
        this.duration = duration;
        this.price = price;
        this.users = users;
        this.dateCreated = dateCreated;
    }

    @Basic
    @Column(name = "duration", nullable = false)
    public int getDuration() {
        return duration;
    }

    public void setDuration(int duration) {
        this.duration = duration;
    }

    @Basic
    @Column(name = "price", nullable = false, precision = 8)
    public BigDecimal getPrice() {
        return price;
    }

    public void setPrice(BigDecimal price) {
        this.price = price;
    }

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


    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        Subscription that = (Subscription) o;

        if (duration != that.duration) return false;
        if (id != that.id) return false;
        if (price != null ? !price.equals(that.price) : that.price != null) return false;
        return users != null ? users.equals(that.users) : that.users == null;
    }

    @Override
    public int hashCode() {
        int result = duration;
        result = 31 * result + (price != null ? price.hashCode() : 0);
        result = 31 * result + (users != null ? users.hashCode() : 0);
        result = 31 * result + id;
        return result;
    }


}
