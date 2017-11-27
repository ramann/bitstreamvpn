package com.company.dev.model.ipsec.domain;

import javax.persistence.*;

@Entity
@Table(name="connections")
public class Connections {
    short id;
    String peerId;
    String virtualIp;
    String ipsecPolicyIn;
    String ipsecPolicyOut;
    boolean disconnected;

    @Id
    @Column(name = "id", nullable = false)
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    public short getId() {
        return id;
    }

    public void setId(short id) {
        this.id = id;
    }

    @Basic
    @Column(name = "peer_id", nullable = false)
    public String getPeerId() {
        return peerId;
    }

    public void setPeerId(String peerId) {
        this.peerId = peerId;
    }

    @Basic
    @Column(name = "virtual_ip", nullable = false)
    public String getVirtualIp() {
        return virtualIp;
    }

    public void setVirtualIp(String virtualIp) {
        this.virtualIp = virtualIp;
    }

    @Basic
    @Column(name = "ipsec_policy_in", nullable = false)
    public String getIpsecPolicyIn() {
        return ipsecPolicyIn;
    }

    public void setIpsecPolicyIn(String ipsecPolicyIn) {
        this.ipsecPolicyIn = ipsecPolicyIn;
    }

    @Basic
    @Column(name = "ipsec_policy_out", nullable = false)
    public String getIpsecPolicyOut() {
        return ipsecPolicyOut;
    }

    public void setIpsecPolicyOut(String ipsecPolicyOut) {
        this.ipsecPolicyOut = ipsecPolicyOut;
    }

    @Basic
    @Column(name = "disconnected", nullable = false)
    public boolean isDisconnected() {
        return disconnected;
    }

    public void setDisconnected(boolean disconnected) {
        this.disconnected = disconnected;
    }

}
