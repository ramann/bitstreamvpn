package com.company.dev.model.ipsec.domain;

import javax.persistence.*;

@Entity
@Table(name = "child_configs", schema = "testipsecdb", catalog = "")
public class ChildConfigs {
    private int id;
    private String name;
    private int lifetime = 1500;
    private int rekeytime = 1200;
    private int jitter = 60;
    private String updown;
    private byte hostaccess = 0;
    private byte mode = 2;
    private byte startAction = 0;
    private byte dpdAction = 0;
    private byte closeAction = 0;
    private byte ipcomp = 0;
    private int reqid = 0;

    public ChildConfigs() {}

    public ChildConfigs(String name, String updown) {
        this.name = name;
        this.updown = updown;
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
    @Column(name = "name", nullable = false, length = 32)
    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    @Basic
    @Column(name = "lifetime", nullable = false)
    public int getLifetime() {
        return lifetime;
    }

    public void setLifetime(int lifetime) {
        this.lifetime = lifetime;
    }

    @Basic
    @Column(name = "rekeytime", nullable = false)
    public int getRekeytime() {
        return rekeytime;
    }

    public void setRekeytime(int rekeytime) {
        this.rekeytime = rekeytime;
    }

    @Basic
    @Column(name = "jitter", nullable = false)
    public int getJitter() {
        return jitter;
    }

    public void setJitter(int jitter) {
        this.jitter = jitter;
    }

    @Basic
    @Column(name = "updown", nullable = true, length = 128)
    public String getUpdown() {
        return updown;
    }

    public void setUpdown(String updown) {
        this.updown = updown;
    }

    @Basic
    @Column(name = "hostaccess", nullable = false)
    public byte getHostaccess() {
        return hostaccess;
    }

    public void setHostaccess(byte hostaccess) {
        this.hostaccess = hostaccess;
    }

    @Basic
    @Column(name = "mode", nullable = false)
    public byte getMode() {
        return mode;
    }

    public void setMode(byte mode) {
        this.mode = mode;
    }

    @Basic
    @Column(name = "start_action", nullable = false)
    public byte getStartAction() {
        return startAction;
    }

    public void setStartAction(byte startAction) {
        this.startAction = startAction;
    }

    @Basic
    @Column(name = "dpd_action", nullable = false)
    public byte getDpdAction() {
        return dpdAction;
    }

    public void setDpdAction(byte dpdAction) {
        this.dpdAction = dpdAction;
    }

    @Basic
    @Column(name = "close_action", nullable = false)
    public byte getCloseAction() {
        return closeAction;
    }

    public void setCloseAction(byte closeAction) {
        this.closeAction = closeAction;
    }

    @Basic
    @Column(name = "ipcomp", nullable = false)
    public byte getIpcomp() {
        return ipcomp;
    }

    public void setIpcomp(byte ipcomp) {
        this.ipcomp = ipcomp;
    }

    @Basic
    @Column(name = "reqid", nullable = false)
    public int getReqid() {
        return reqid;
    }

    public void setReqid(int reqid) {
        this.reqid = reqid;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        ChildConfigs that = (ChildConfigs) o;

        if (id != that.id) return false;
        if (lifetime != that.lifetime) return false;
        if (rekeytime != that.rekeytime) return false;
        if (jitter != that.jitter) return false;
        if (hostaccess != that.hostaccess) return false;
        if (mode != that.mode) return false;
        if (startAction != that.startAction) return false;
        if (dpdAction != that.dpdAction) return false;
        if (closeAction != that.closeAction) return false;
        if (ipcomp != that.ipcomp) return false;
        if (reqid != that.reqid) return false;
        if (name != null ? !name.equals(that.name) : that.name != null) return false;
        if (updown != null ? !updown.equals(that.updown) : that.updown != null) return false;

        return true;
    }

    @Override
    public int hashCode() {
        int result = id;
        result = 31 * result + (name != null ? name.hashCode() : 0);
        result = 31 * result + lifetime;
        result = 31 * result + rekeytime;
        result = 31 * result + jitter;
        result = 31 * result + (updown != null ? updown.hashCode() : 0);
        result = 31 * result + (int) hostaccess;
        result = 31 * result + (int) mode;
        result = 31 * result + (int) startAction;
        result = 31 * result + (int) dpdAction;
        result = 31 * result + (int) closeAction;
        result = 31 * result + (int) ipcomp;
        result = 31 * result + reqid;
        return result;
    }
}
