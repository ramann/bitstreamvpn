package com.company.dev.model.app.domain;

import javax.persistence.*;
import java.math.BigDecimal;

@Entity
public class Subscription {
    private int duration;
    private BigDecimal price;
    private Users users;
    private int id;

    public Subscription() {}

    public Subscription(Subscription subscription) {
        this.id = subscription.getId();
        this.duration = subscription.getDuration();
        this.price = subscription.getPrice();
        this.users = subscription.getUsers();
        this.id = subscription.getId();
    }

    public Subscription(int id) {
        this.id = id;
    }

    public Subscription(int duration, BigDecimal price, Users users) {
        this.duration = duration;
        this.price = price;
        this.users = users;
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

    @Id
    @SequenceGenerator(allocationSize=1, initialValue=1, sequenceName="subscription_id_seq", name="subscription_id_seq")
    @GeneratedValue(generator="subscription_id_seq", strategy=GenerationType.SEQUENCE)
    @Column(name = "id", nullable = false)
    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
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
