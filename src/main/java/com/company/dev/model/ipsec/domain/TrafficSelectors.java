package com.company.dev.model.ipsec.domain;

import javax.persistence.*;
import java.util.Arrays;

@Entity
@Table(name = "traffic_selectors", schema = "testipsecdb", catalog = "")
public class TrafficSelectors {
    private int id;
    private byte type = 7;
    private short protocol = 0;
    private byte[] startAddr;
    private byte[] endAddr;
    private short startPort = 0;
    private int endPort = 65535;

    public TrafficSelectors() {}

    public TrafficSelectors(byte type) {
        this.type = type;
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
    @Column(name = "type", nullable = false)
    public byte getType() {
        return type;
    }

    public void setType(byte type) {
        this.type = type;
    }

    @Basic
    @Column(name = "protocol", nullable = false)
    public short getProtocol() {
        return protocol;
    }

    public void setProtocol(short protocol) {
        this.protocol = protocol;
    }

    @Basic
    @Column(name = "start_addr", nullable = true)
    public byte[] getStartAddr() {
        return startAddr;
    }

    public void setStartAddr(byte[] startAddr) {
        this.startAddr = startAddr;
    }

    @Basic
    @Column(name = "end_addr", nullable = true)
    public byte[] getEndAddr() {
        return endAddr;
    }

    public void setEndAddr(byte[] endAddr) {
        this.endAddr = endAddr;
    }

    @Basic
    @Column(name = "start_port", nullable = false)
    public short getStartPort() {
        return startPort;
    }

    public void setStartPort(short startPort) {
        this.startPort = startPort;
    }

    @Basic
    @Column(name = "end_port", nullable = false)
    public int getEndPort() {
        return endPort;
    }

    public void setEndPort(int endPort) {
        this.endPort = endPort;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        TrafficSelectors that = (TrafficSelectors) o;

        if (id != that.id) return false;
        if (type != that.type) return false;
        if (protocol != that.protocol) return false;
        if (startPort != that.startPort) return false;
        if (endPort != that.endPort) return false;
        if (!Arrays.equals(startAddr, that.startAddr)) return false;
        if (!Arrays.equals(endAddr, that.endAddr)) return false;

        return true;
    }

    @Override
    public int hashCode() {
        int result = id;
        result = 31 * result + (int) type;
        result = 31 * result + (int) protocol;
        result = 31 * result + Arrays.hashCode(startAddr);
        result = 31 * result + Arrays.hashCode(endAddr);
        result = 31 * result + (int) startPort;
        result = 31 * result + (int) endPort;
        return result;
    }
}
