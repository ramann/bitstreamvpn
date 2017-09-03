package com.company.dev.model.ipsec.domain;

import javax.persistence.*;
import java.util.Arrays;

@Entity
@Table(name="addresses")
public class Addresses {
    private int id;
    private int pool;
    private byte[] address;
    private int identity;
    private int acquired;
    private int released;

    public Addresses() {}

    public Addresses(int pool, byte[] address) {
        this.pool = pool;
        this.address = address;
    }

    @Id
    @Column(name = "id", nullable = false)
    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }

    @Basic
    @Column(name = "pool", nullable = false)
    public int getPool() {
        return pool;
    }

    public void setPool(int pool) {
        this.pool = pool;
    }

    @Basic
    @Column(name = "address", nullable = false)
    public byte[] getAddress() {
        return address;
    }

    public void setAddress(byte[] address) {
        this.address = address;
    }

    @Basic
    @Column(name = "identity", nullable = false)
    public int getIdentity() {
        return identity;
    }

    public void setIdentity(int identity) {
        this.identity = identity;
    }

    @Basic
    @Column(name = "acquired", nullable = false)
    public int getAcquired() {
        return acquired;
    }

    public void setAcquired(int acquired) {
        this.acquired = acquired;
    }

    @Basic
    @Column(name = "released", nullable = false)
    public int getReleased() {
        return released;
    }

    public void setReleased(int released) {
        this.released = released;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        Addresses addresses = (Addresses) o;

        if (id != addresses.id) return false;
        if (pool != addresses.pool) return false;
        if (identity != addresses.identity) return false;
        if (acquired != addresses.acquired) return false;
        if (released != addresses.released) return false;
        if (!Arrays.equals(address, addresses.address)) return false;

        return true;
    }

    @Override
    public int hashCode() {
        int result = id;
        result = 31 * result + pool;
        result = 31 * result + Arrays.hashCode(address);
        result = 31 * result + identity;
        result = 31 * result + acquired;
        result = 31 * result + released;
        return result;
    }
}
