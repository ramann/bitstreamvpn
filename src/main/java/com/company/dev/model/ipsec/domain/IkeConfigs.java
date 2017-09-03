package com.company.dev.model.ipsec.domain;

import javax.persistence.*;

@Entity
@Table(name = "ike_configs", schema = "testipsecdb", catalog = "")
public class IkeConfigs {
    private int id;
    private byte certreq;
    private byte forceEncap;
    private String local;
    private String remote;

    public IkeConfigs() {}

    public IkeConfigs(String local, String remote) {
        this.local = local;
        this.remote = remote;
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
    @Column(name = "certreq", nullable = false)
    public byte getCertreq() {
        return certreq;
    }

    public void setCertreq(byte certreq) {
        this.certreq = certreq;
    }

    @Basic
    @Column(name = "force_encap", nullable = false)
    public byte getForceEncap() {
        return forceEncap;
    }

    public void setForceEncap(byte forceEncap) {
        this.forceEncap = forceEncap;
    }

    @Basic
    @Column(name = "local", nullable = false, length = 128)
    public String getLocal() {
        return local;
    }

    public void setLocal(String local) {
        this.local = local;
    }

    @Basic
    @Column(name = "remote", nullable = false, length = 128)
    public String getRemote() {
        return remote;
    }

    public void setRemote(String remote) {
        this.remote = remote;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        IkeConfigs that = (IkeConfigs) o;

        if (id != that.id) return false;
        if (certreq != that.certreq) return false;
        if (forceEncap != that.forceEncap) return false;
        if (local != null ? !local.equals(that.local) : that.local != null) return false;
        if (remote != null ? !remote.equals(that.remote) : that.remote != null) return false;

        return true;
    }

    @Override
    public int hashCode() {
        int result = id;
        result = 31 * result + (int) certreq;
        result = 31 * result + (int) forceEncap;
        result = 31 * result + (local != null ? local.hashCode() : 0);
        result = 31 * result + (remote != null ? remote.hashCode() : 0);
        return result;
    }
}
