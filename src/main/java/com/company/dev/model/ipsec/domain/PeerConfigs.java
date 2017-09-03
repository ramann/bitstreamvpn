package com.company.dev.model.ipsec.domain;

import javax.persistence.*;

@Entity
@Table(name = "peer_configs", schema = "testipsecdb", catalog = "")
public class PeerConfigs {
    private int id;
    private String name;
    private byte ikeVersion;
    private int ikeCfg;
    private String localId;
    private String remoteId;
    private byte certPolicy;
    private byte uniqueid;
    private byte authMethod;
    private byte eapType;
    private short eapVendor;
    private byte keyingtries;
    private int rekeytime;
    private int reauthtime;
    private int jitter;
    private int overtime;
    private byte mobike;
    private int dpdDelay;
    private String virtual;
    private String pool;
    private byte mediation;
    private int mediatedBy;
    private int peerId;

    public PeerConfigs() {}

    public PeerConfigs(String name, int ikeCfg, String localId, String remoteId, String pool) {
        this.name = name;
        this.ikeCfg = ikeCfg;
        this.localId = localId;
        this.remoteId = remoteId;
        this.pool =  pool;
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
    @Column(name = "name", nullable = false, length = 32)
    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    @Basic
    @Column(name = "ike_version", nullable = false)
    public byte getIkeVersion() {
        return ikeVersion;
    }

    public void setIkeVersion(byte ikeVersion) {
        this.ikeVersion = ikeVersion;
    }

    @Basic
    @Column(name = "ike_cfg", nullable = false)
    public int getIkeCfg() {
        return ikeCfg;
    }

    public void setIkeCfg(int ikeCfg) {
        this.ikeCfg = ikeCfg;
    }

    @Basic
    @Column(name = "local_id", nullable = false, length = 64)
    public String getLocalId() {
        return localId;
    }

    public void setLocalId(String localId) {
        this.localId = localId;
    }

    @Basic
    @Column(name = "remote_id", nullable = false, length = 64)
    public String getRemoteId() {
        return remoteId;
    }

    public void setRemoteId(String remoteId) {
        this.remoteId = remoteId;
    }

    @Basic
    @Column(name = "cert_policy", nullable = false)
    public byte getCertPolicy() {
        return certPolicy;
    }

    public void setCertPolicy(byte certPolicy) {
        this.certPolicy = certPolicy;
    }

    @Basic
    @Column(name = "uniqueid", nullable = false)
    public byte getUniqueid() {
        return uniqueid;
    }

    public void setUniqueid(byte uniqueid) {
        this.uniqueid = uniqueid;
    }

    @Basic
    @Column(name = "auth_method", nullable = false)
    public byte getAuthMethod() {
        return authMethod;
    }

    public void setAuthMethod(byte authMethod) {
        this.authMethod = authMethod;
    }

    @Basic
    @Column(name = "eap_type", nullable = false)
    public byte getEapType() {
        return eapType;
    }

    public void setEapType(byte eapType) {
        this.eapType = eapType;
    }

    @Basic
    @Column(name = "eap_vendor", nullable = false)
    public short getEapVendor() {
        return eapVendor;
    }

    public void setEapVendor(short eapVendor) {
        this.eapVendor = eapVendor;
    }

    @Basic
    @Column(name = "keyingtries", nullable = false)
    public byte getKeyingtries() {
        return keyingtries;
    }

    public void setKeyingtries(byte keyingtries) {
        this.keyingtries = keyingtries;
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
    @Column(name = "reauthtime", nullable = false)
    public int getReauthtime() {
        return reauthtime;
    }

    public void setReauthtime(int reauthtime) {
        this.reauthtime = reauthtime;
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
    @Column(name = "overtime", nullable = false)
    public int getOvertime() {
        return overtime;
    }

    public void setOvertime(int overtime) {
        this.overtime = overtime;
    }

    @Basic
    @Column(name = "mobike", nullable = false)
    public byte getMobike() {
        return mobike;
    }

    public void setMobike(byte mobike) {
        this.mobike = mobike;
    }

    @Basic
    @Column(name = "dpd_delay", nullable = false)
    public int getDpdDelay() {
        return dpdDelay;
    }

    public void setDpdDelay(int dpdDelay) {
        this.dpdDelay = dpdDelay;
    }

    @Basic
    @Column(name = "virtual", nullable = true, length = 40)
    public String getVirtual() {
        return virtual;
    }

    public void setVirtual(String virtual) {
        this.virtual = virtual;
    }

    @Basic
    @Column(name = "pool", nullable = true, length = 32)
    public String getPool() {
        return pool;
    }

    public void setPool(String pool) {
        this.pool = pool;
    }

    @Basic
    @Column(name = "mediation", nullable = false)
    public byte getMediation() {
        return mediation;
    }

    public void setMediation(byte mediation) {
        this.mediation = mediation;
    }

    @Basic
    @Column(name = "mediated_by", nullable = false)
    public int getMediatedBy() {
        return mediatedBy;
    }

    public void setMediatedBy(int mediatedBy) {
        this.mediatedBy = mediatedBy;
    }

    @Basic
    @Column(name = "peer_id", nullable = false)
    public int getPeerId() {
        return peerId;
    }

    public void setPeerId(int peerId) {
        this.peerId = peerId;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        PeerConfigs that = (PeerConfigs) o;

        if (id != that.id) return false;
        if (ikeVersion != that.ikeVersion) return false;
        if (ikeCfg != that.ikeCfg) return false;
        if (certPolicy != that.certPolicy) return false;
        if (uniqueid != that.uniqueid) return false;
        if (authMethod != that.authMethod) return false;
        if (eapType != that.eapType) return false;
        if (eapVendor != that.eapVendor) return false;
        if (keyingtries != that.keyingtries) return false;
        if (rekeytime != that.rekeytime) return false;
        if (reauthtime != that.reauthtime) return false;
        if (jitter != that.jitter) return false;
        if (overtime != that.overtime) return false;
        if (mobike != that.mobike) return false;
        if (dpdDelay != that.dpdDelay) return false;
        if (mediation != that.mediation) return false;
        if (mediatedBy != that.mediatedBy) return false;
        if (peerId != that.peerId) return false;
        if (name != null ? !name.equals(that.name) : that.name != null) return false;
        if (localId != null ? !localId.equals(that.localId) : that.localId != null) return false;
        if (remoteId != null ? !remoteId.equals(that.remoteId) : that.remoteId != null) return false;
        if (virtual != null ? !virtual.equals(that.virtual) : that.virtual != null) return false;
        if (pool != null ? !pool.equals(that.pool) : that.pool != null) return false;

        return true;
    }

    @Override
    public int hashCode() {
        int result = id;
        result = 31 * result + (name != null ? name.hashCode() : 0);
        result = 31 * result + (int) ikeVersion;
        result = 31 * result + ikeCfg;
        result = 31 * result + (localId != null ? localId.hashCode() : 0);
        result = 31 * result + (remoteId != null ? remoteId.hashCode() : 0);
        result = 31 * result + (int) certPolicy;
        result = 31 * result + (int) uniqueid;
        result = 31 * result + (int) authMethod;
        result = 31 * result + (int) eapType;
        result = 31 * result + (int) eapVendor;
        result = 31 * result + (int) keyingtries;
        result = 31 * result + rekeytime;
        result = 31 * result + reauthtime;
        result = 31 * result + jitter;
        result = 31 * result + overtime;
        result = 31 * result + (int) mobike;
        result = 31 * result + dpdDelay;
        result = 31 * result + (virtual != null ? virtual.hashCode() : 0);
        result = 31 * result + (pool != null ? pool.hashCode() : 0);
        result = 31 * result + (int) mediation;
        result = 31 * result + mediatedBy;
        result = 31 * result + peerId;
        return result;
    }
}
