package com.company.dev.model.ipsec.domain;

import javax.persistence.Column;
import javax.persistence.Id;
import java.io.Serializable;

public class PeerConfigChildConfigPK implements Serializable {
    private int peerCfg;
    private int childCfg;

    @Column(name = "peer_cfg", nullable = false)
    @Id
    public int getPeerCfg() {
        return peerCfg;
    }

    public void setPeerCfg(int peerCfg) {
        this.peerCfg = peerCfg;
    }

    @Column(name = "child_cfg", nullable = false)
    @Id
    public int getChildCfg() {
        return childCfg;
    }

    public void setChildCfg(int childCfg) {
        this.childCfg = childCfg;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        PeerConfigChildConfigPK that = (PeerConfigChildConfigPK) o;

        if (peerCfg != that.peerCfg) return false;
        if (childCfg != that.childCfg) return false;

        return true;
    }

    @Override
    public int hashCode() {
        int result = peerCfg;
        result = 31 * result + childCfg;
        return result;
    }
}
