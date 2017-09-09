package com.company.dev.util;

import java.sql.Timestamp;
import java.util.Date;

public class Timespan {
    private Timestamp begin;
    private Timestamp end;

    public Timespan(Timestamp begin, Timestamp end) {
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
}
