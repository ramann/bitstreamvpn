package com.company.dev.model.ipsec.domain;

import javax.persistence.*;
import java.util.Arrays;

@Entity
@Table(name = "private_keys", schema = "testipsecdb", catalog = "")
public class PrivateKeys {
    private int id;
    private byte type;
    private byte[] data;

    @Id
    @Column(name = "id", nullable = false)
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

        PrivateKeys that = (PrivateKeys) o;

        if (id != that.id) return false;
        if (type != that.type) return false;
        if (!Arrays.equals(data, that.data)) return false;

        return true;
    }

    @Override
    public int hashCode() {
        int result = id;
        result = 31 * result + (int) type;
        result = 31 * result + Arrays.hashCode(data);
        return result;
    }
}
