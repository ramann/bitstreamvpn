package com.company.dev.model.app.domain;

import javax.persistence.*;
import java.math.BigInteger;

@Entity
@Table(name="subscription_package")
public class SubscriptionPackage {
    private int id;
    private String name;
    private int duration;
    private int certs;
    private BigInteger bytes;
    private double price;

    @Id
    @Column(name = "id", nullable = false)
    @GeneratedValue(strategy= GenerationType.IDENTITY)
    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }

    @Basic
    @Column(name = "name", nullable = false)
    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
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
    @Column(name = "certs", nullable = false)
    public int getCerts() {
        return certs;
    }

    public void setCerts(int certs) {
        this.certs = certs;
    }

    @Basic
    @Column(name = "bytes", nullable = false)
    public BigInteger getBytes() {
        return bytes;
    }

    public void setBytes(BigInteger bytes) {
        this.bytes = bytes;
    }

    @Basic
    @Column(name = "price", nullable = false, precision = 2)
    public double getPrice() {
        return price;
    }

    public void setPrice(double price) {
        this.price = price;
    }
}
