
INSERT INTO certificates (
   type, keytype, data
) VALUES ( /* "C=US, O=test, CN=peer1" */
			/* ./bin2sql dbtest-server1.pem # cat dbtest-server2.pem | openssl x509 -outform der -inform pem | xxd -p | tr -d '\n' && echo */
  1, 1, X'308202fe308201e6a0030201020208501b15a20217ca60300d06092a864886f70d01010b0500302d310b3009060355040613025553310d300b060355040a130474657374310f300d06035504031306746573744341301e170d3137303833303233343831395a170d3230303832393233343831395a302c310b3009060355040613025553310d300b060355040a130474657374310e300c06035504031305706565723130820122300d06092a864886f70d01010105000382010f003082010a0282010100b0f3989484153504f45584b8d150b7fe3e269c8d62c0623f3d3f7ac1eac95b03f0b67cb4ecc5cc1e95ab1f0905a7f47e5ecd7ca1797baad115a394a57f902e4e6b9b5676ef8726a132ebdef6c8d985f8c2c949e81364f4e70e643bae1118570b969bacd818757eee784daf1b2d5ae1e8d955d75672ed35a25c1297faf9552e39ce0068e883dae6a89416686afd2d64b4be79eea60431624089f16a84dcc7eb4ab816a029485e51856b60a79b44989fea7b7fb667ebd1e106a5ab07cb38d5f33fc91bdd4a84a69e3e915a8997250e38b4c48174d19fc0784ed4bb7f52ca9815c19cb257fbd0d2cf754dc1a53f08e2248dae03a49dc9b5fd4e91fbb620046035730203010001a3233021301f0603551d230418301680142485d6c13ea7cf7f25f4a18ab5d4661ea0282a78300d06092a864886f70d01010b0500038201010062a7672615fb44754a033dacc11e2beaa4d2140c72c302b5a64a334d6b15efed651523ae4ca24e9ed68863475829bb4ff4a080b49de1bbb50e1667e4274782855ce840a3f19ce58de1adbebf8591c22471ca5f44a894922c07bf5ad09ca86e61b17d9773cb29dbc16f1094af222f352aa6264b8b4627f20e2bd8f9b2f801fa60d2343568606134a5ad6c385e728e2b2defc00407ac6cda7c1356e926f29d8ed28ea0c3857ad09f20b3c443ed1f998027a352a20b62f53d63f3bde6177eae2e885fc33922b1f4acc367896e22666bb16285d9d9f249bb58ba865d01a497d511156952f4d333b0f1caa6d0583c2def71e57275322fd6c414f916af19b13da34398'
);

insert into identities (
 type, data
) values ( /* id2sql "C=US, O=test, CN=peer1" */
 9, X'302c310b3009060355040613025553310d300b060355040a130474657374310e300c060355040313057065657231'
);

INSERT INTO certificate_identity (
  certificate, identity
) VALUES (
  3, 7
);

/* Configurations */

INSERT INTO ike_configs (
  local, remote
) VALUES (
  '174.138.46.113', '0.0.0.0'
);

INSERT INTO peer_configs (
  name, ike_cfg, local_id, remote_id, pool
) VALUES (
  'rw', 1, 4, 7, 'bigpool'
);

INSERT INTO child_configs (
  name, updown
) VALUES (
  'rw', '/usr/local/libexec/ipsec/_updown iptables'
);

INSERT INTO peer_config_child_config (
  peer_cfg, child_cfg
) VALUES (
  1, 1
);

INSERT INTO traffic_selectors (
  type
) VALUES (
  7
);

INSERT INTO traffic_selectors (
  type
) VALUES ( /* dynamic/32 */
  7
);

INSERT INTO child_config_traffic_selector (
  child_cfg, traffic_selector, kind
) VALUES (
  1, 1, 2
);

INSERT INTO child_config_traffic_selector (
  child_cfg, traffic_selector, kind
) VALUES (
  1, 2, 3
);
