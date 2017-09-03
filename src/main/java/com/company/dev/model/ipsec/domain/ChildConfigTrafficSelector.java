package com.company.dev.model.ipsec.domain;

import javax.persistence.*;

@Entity
@Table(name = "child_config_traffic_selector", schema = "testipsecdb", catalog = "")
public class ChildConfigTrafficSelector {
    private int id;
    private int childCfg;
    private int trafficSelector;
    private byte kind;

    public ChildConfigTrafficSelector() {}

    public ChildConfigTrafficSelector(int childCfg, int trafficSelector, byte kind) {
        this.childCfg = childCfg;
        this.trafficSelector = trafficSelector;
        this.kind = kind;
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
    @Column(name = "child_cfg", nullable = false)
    public int getChildCfg() {
        return childCfg;
    }

    public void setChildCfg(int childCfg) {
        this.childCfg = childCfg;
    }

    @Basic
    @Column(name = "traffic_selector", nullable = false)
    public int getTrafficSelector() {
        return trafficSelector;
    }

    public void setTrafficSelector(int trafficSelector) {
        this.trafficSelector = trafficSelector;
    }

    @Basic
    @Column(name = "kind", nullable = false)
    public byte getKind() {
        return kind;
    }

    public void setKind(byte kind) {
        this.kind = kind;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        ChildConfigTrafficSelector that = (ChildConfigTrafficSelector) o;

        if (id != that.id) return false;
        if (childCfg != that.childCfg) return false;
        if (trafficSelector != that.trafficSelector) return false;
        if (kind != that.kind) return false;

        return true;
    }

    @Override
    public int hashCode() {
        int result = id;
        result = 31 * result + childCfg;
        result = 31 * result + trafficSelector;
        result = 31 * result + (int) kind;
        return result;
    }
}
