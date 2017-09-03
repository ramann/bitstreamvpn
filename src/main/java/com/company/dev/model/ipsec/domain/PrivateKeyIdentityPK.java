package com.company.dev.model.ipsec.domain;

import javax.persistence.Column;
import javax.persistence.Id;
import java.io.Serializable;

public class PrivateKeyIdentityPK implements Serializable {
    private int privateKey;
    private int identity;

    @Column(name = "private_key", nullable = false)
    @Id
    public int getPrivateKey() {
        return privateKey;
    }

    public void setPrivateKey(int privateKey) {
        this.privateKey = privateKey;
    }

    @Column(name = "identity", nullable = false)
    @Id
    public int getIdentity() {
        return identity;
    }

    public void setIdentity(int identity) {
        this.identity = identity;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        PrivateKeyIdentityPK that = (PrivateKeyIdentityPK) o;

        if (privateKey != that.privateKey) return false;
        if (identity != that.identity) return false;

        return true;
    }

    @Override
    public int hashCode() {
        int result = privateKey;
        result = 31 * result + identity;
        return result;
    }
}
