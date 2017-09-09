package com.company.dev.util;

import java.sql.Timestamp;
import java.util.Date;

public class TimeSpan {
    private Timestamp begin;
    private Timestamp end;

    public TimeSpan(Timestamp begin, Timestamp end) {
        this.begin = begin;
        this.end = end;
    }

    public Timestamp getBegin() {
        return begin;
    }

    public void setBegin(Timestamp begin) {
        this.begin = begin;
    }

    public Timestamp getEnd() {
        return end;
    }

    public void setEnd(Timestamp end) {
        this.end = end;
    }

    @Override
    public String toString() {
        return "TimeSpan{" +
                "begin=" + begin +
                ", end=" + end +
                '}';
    }
}
