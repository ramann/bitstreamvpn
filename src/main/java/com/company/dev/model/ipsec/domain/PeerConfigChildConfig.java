package com.company.dev.model.ipsec.domain;

import javax.persistence.*;

@Entity
@Table(name = "peer_config_child_config", schema = "testipsecdb", catalog = "")
@IdClass(PeerConfigChildConfigPK.class)
public class PeerConfigChildConfig {
    private int peerCfg;
    private int childCfg;

    public PeerConfigChildConfig() {}

    public PeerConfigChildConfig(int peerCfg, int childCfg) {
        this.peerCfg = peerCfg;
        this.childCfg = childCfg;
    }

    @Id
    @Column(name = "peer_cfg", nullable = false)
    public int getPeerCfg() {
        return peerCfg;
    }

    public void setPeerCfg(int peerCfg) {
        this.peerCfg = peerCfg;
    }

    @Id
    @Column(name = "child_cfg", nullable = false)
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

        PeerConfigChildConfig that = (PeerConfigChildConfig) o;

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
