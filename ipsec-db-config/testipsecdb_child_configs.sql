INSERT INTO testipsecdb.child_configs (name, lifetime, rekeytime, jitter, updown, hostaccess, mode, start_action, dpd_action, close_action, ipcomp, reqid) VALUES ('rw', 1500, 1200, 60, '/usr/local/libexec/ipsec/_updown iptables', 0, 2, 0, 0, 0, 0, 0);