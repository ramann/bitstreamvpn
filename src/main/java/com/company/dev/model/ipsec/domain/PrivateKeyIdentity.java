package com.company.dev.model.ipsec.domain;

import javax.persistence.*;

@Entity
@Table(name = "private_key_identity", schema = "testipsecdb", catalog = "")
@IdClass(PrivateKeyIdentityPK.class)
public class PrivateKeyIdentity {
    private int privateKey;
    private int identity;

    @Id
    @Column(name = "private_key", nullable = false)
    public int getPrivateKey() {
        return privateKey;
    }

    public void setPrivateKey(int privateKey) {
        this.privateKey = privateKey;
    }

    @Id
    @Column(name = "identity", nullable = false)
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

        PrivateKeyIdentity that = (PrivateKeyIdentity) o;

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
