package com.company.dev.model.ipsec.domain;

import javax.persistence.*;
import java.util.Arrays;

@Entity
@Table(name="certificates")
public class Certificates {
    private int id;
    private byte type;
    private byte keytype;
    private byte[] data;

    public Certificates() {}

    public Certificates(byte type, byte keytype, byte[] data) {
        this.type = type;
        this.keytype = keytype;
        this.data = data;
    }

    @Id
    @Column(name = "id", nullable = false)
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }

    @Basic
    @Column(name = "type", nullable = false)
    public byte getType() {
        return type;
    }

    public void setType(byte type) {
        this.type = type;
    }

    @Basic
    @Column(name = "keytype", nullable = false)
    public byte getKeytype() {
        return keytype;
    }

    public void setKeytype(byte keytype) {
        this.keytype = keytype;
    }

    @Basic
    @Column(name = "data", nullable = false)
    public byte[] getData() {
        return data;
    }

    public void setData(byte[] data) {
        this.data = data;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        Certificates that = (Certificates) o;

        if (id != that.id) return false;
        if (type != that.type) return false;
        if (keytype != that.keytype) return false;
        if (!Arrays.equals(data, that.data)) return false;

        return true;
    }

    @Override
    public int hashCode() {
        int result = id;
        result = 31 * result + (int) type;
        result = 31 * result + (int) keytype;
        result = 31 * result + Arrays.hashCode(data);
        return result;
    }

    @Override
    public String toString() {
        return "Certificates{" +
                "id=" + id +
                ", type=" + type +
                ", keytype=" + keytype +
                ", data=" + Arrays.toString(data) +
                '}';
    }
}
