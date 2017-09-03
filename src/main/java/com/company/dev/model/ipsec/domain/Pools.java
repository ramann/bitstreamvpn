package com.company.dev.model.ipsec.domain;

import javax.persistence.Basic;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Id;
import java.util.Arrays;

@Entity
public class Pools {
    private int id;
    private String name;
    private byte[] start;
    private byte[] end;
    private int timeout;

    public Pools(){}

    public Pools(String name, byte[] start, byte[] end, int timeout) {
        this.name = name;
        this.start = start;
        this.end = end;
        this.timeout = timeout;
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
    @Column(name = "name", nullable = false, length = 32)
    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    @Basic
    @Column(name = "start", nullable = false)
    public byte[] getStart() {
        return start;
    }

    public void setStart(byte[] start) {
        this.start = start;
    }

    @Basic
    @Column(name = "end", nullable = false)
    public byte[] getEnd() {
        return end;
    }

    public void setEnd(byte[] end) {
        this.end = end;
    }

    @Basic
    @Column(name = "timeout", nullable = false)
    public int getTimeout() {
        return timeout;
    }

    public void setTimeout(int timeout) {
        this.timeout = timeout;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        Pools pools = (Pools) o;

        if (id != pools.id) return false;
        if (timeout != pools.timeout) return false;
        if (name != null ? !name.equals(pools.name) : pools.name != null) return false;
        if (!Arrays.equals(start, pools.start)) return false;
        if (!Arrays.equals(end, pools.end)) return false;

        return true;
    }

    @Override
    public int hashCode() {
        int result = id;
        result = 31 * result + (name != null ? name.hashCode() : 0);
        result = 31 * result + Arrays.hashCode(start);
        result = 31 * result + Arrays.hashCode(end);
        result = 31 * result + timeout;
        return result;
    }
}
