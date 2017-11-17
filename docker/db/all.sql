-- create databases and users

create database test1;
create user 'test1' identified by 'testing';
grant all privileges on test1.* to 'test1';

create database testipsecdb;
create user 'testipsecuser' identified by 'testing';
grant all privileges on testipsecdb.* to 'testipsecuser';

-- app database

use test1;
--
-- Name: users; Type: TABLE; Schema: public; Owner: test1
--
drop table if exists payment;
drop table if exists certificate;
drop table if exists subscription;
drop table if exists users;

CREATE TABLE users (
    username varchar(30) NOT NULL primary key,
    password varbinary(256) NOT NULL, -- password varchar(64) NOT NULL,
    salt varbinary(64) NOT NULL -- salt varchar(16) NOT NULL
);

LOCK TABLES `users` WRITE;
/*!40000 ALTER TABLE `users` DISABLE KEYS */;
INSERT INTO `users` VALUES ('apiuser',0x0083E0069FAE0845B3A45AC8ABED8C8C68F05033494B1B4A5226F2562D9E3120,0xBF3CED69DEA1E99D);
/*!40000 ALTER TABLE `users` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Name: subscription; Type: TABLE; Schema: public; Owner: test1
--
CREATE TABLE subscription (
    duration integer NOT NULL,
    price numeric(11,8) NOT NULL,
    username varchar(30) NOT NULL,
    id integer unsigned NOT NULL auto_increment,
    date_created timestamp NOT NULL,
    primary key (id),
    FOREIGN KEY (username) REFERENCES users(username)
);


--
-- Name: certificate; Type: TABLE; Schema: public; Owner: test1
--
CREATE TABLE certificate (
    id integer unsigned not null auto_increment,
    date_initiated timestamp,
    csr_text varchar(4096),
    signed boolean,
    cert_text varchar(4096),
    revoked boolean,
    serial bigint,
    subscription integer unsigned NOT NULL,
    date_created timestamp,
    subject varchar(100) NOT NULL,
    primary key (id),
    constraint FK_SubscriptionCertificate
    FOREIGN KEY (subscription) REFERENCES subscription(id)
);


--
-- Name: payment; Type: TABLE; Schema: public; Owner: test1
--
CREATE TABLE payment (
    id integer unsigned not null auto_increment primary key,
    date_initiated timestamp,
    amount numeric(11,8),
    receiving_address varchar(40) NOT NULL,
    date_confirm_1 timestamp,
    date_confirm_3 timestamp,
    date_confirm_6 timestamp,
    subscription integer unsigned NOT NULL,
    in_error boolean NOT NULL,
    date_created timestamp NOT NULL,
    amount_expecting numeric(11,8) NOT NULL,
    bandwidth BIGINT UNSIGNED DEFAULT 0,
    date_start TIMESTAMP,
    date_end TIMESTAMP,
    unique (receiving_address),
    FOREIGN KEY (subscription) REFERENCES subscription(id)
);

-- strongswan database

use testipsecdb;

drop table if exists `bandwidth`; -- rename this, it just maps nflog group number (id) to peer's subject (peer_id)
create table `bandwidth` (
  `id` SMALLINT(2) unsigned not null AUTO_INCREMENT, -- nflog group number
  `peer_id` VARCHAR(100) NOT NULL,
  `virtual_ip` VARCHAR(40) NOT NULL,
  `ipsec_policy_in` VARCHAR(100) NOT NULL,
  `ipsec_policy_out` VARCHAR(100) NOT NULL,
  PRIMARY KEY (`id`)
);

DROP TABLE IF EXISTS `identities`;

CREATE TABLE `identities` (

  `id` int(10) unsigned NOT NULL auto_increment,

  `type` tinyint(4) unsigned NOT NULL,

  `data` varbinary(200) NOT NULL,

  PRIMARY KEY (`id`),

  UNIQUE (`type`, `data`)

) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci;

DROP TABLE IF EXISTS `child_configs`;

CREATE TABLE `child_configs` (

  `id` int(10) unsigned NOT NULL auto_increment,

  `name` varchar(32) collate utf8_unicode_ci NOT NULL,

  `lifetime` mediumint(8) unsigned NOT NULL default '1500',

  `rekeytime` mediumint(8) unsigned NOT NULL default '1200',

  `jitter` mediumint(8) unsigned NOT NULL default '60',

  `updown` varchar(128) collate utf8_unicode_ci default NULL,

  `hostaccess` tinyint(1) unsigned NOT NULL default '0',

  `mode` tinyint(4) unsigned NOT NULL default '2',

  `start_action` tinyint(4) unsigned NOT NULL default '0',

  `dpd_action` tinyint(4) unsigned NOT NULL default '0',

  `close_action` tinyint(4) unsigned NOT NULL default '0',

  `ipcomp` tinyint(4) unsigned NOT NULL default '0',

  `reqid` mediumint(8) unsigned NOT NULL default '0',

  PRIMARY KEY (`id`),

  INDEX (`name`)

) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci;

DROP TABLE IF EXISTS `child_config_traffic_selector`;

CREATE TABLE `child_config_traffic_selector` (

  `id` int(10) unsigned NOT NULL auto_increment,

  `child_cfg` int(10) unsigned NOT NULL,

  `traffic_selector` int(10) unsigned NOT NULL,

  `kind` tinyint(3) unsigned NOT NULL,

  PRIMARY KEY (`id`),

  INDEX (`child_cfg`, `traffic_selector`)

) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci;

DROP TABLE IF EXISTS `proposals`;

CREATE TABLE `proposals` (

  `id` int(10) unsigned NOT NULL auto_increment,

  `proposal` varchar(128) NOT NULL,

  PRIMARY KEY (`id`)

) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci;

DROP TABLE IF EXISTS `child_config_proposal`;

CREATE TABLE `child_config_proposal` (

  `child_cfg` int(10) unsigned NOT NULL,

  `prio` smallint(5) unsigned NOT NULL,

  `prop` int(10) unsigned NOT NULL

) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci;

DROP TABLE IF EXISTS `ike_configs`;

CREATE TABLE `ike_configs` (

  `id` int(10) unsigned NOT NULL auto_increment,

  `certreq` tinyint(3) unsigned NOT NULL default '1',

  `force_encap` tinyint(1) NOT NULL default '0',

  `local` varchar(128) collate utf8_unicode_ci NOT NULL,

  `remote` varchar(128) collate utf8_unicode_ci NOT NULL,

  PRIMARY KEY (`id`)

) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci;

DROP TABLE IF EXISTS `ike_config_proposal`;

CREATE TABLE `ike_config_proposal` (

  `ike_cfg` int(10) unsigned NOT NULL,

  `prio` smallint(5) unsigned NOT NULL,

  `prop` int(10) unsigned NOT NULL

) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci;

DROP TABLE IF EXISTS `peer_configs`;

CREATE TABLE `peer_configs` (

  `id` int(10) unsigned NOT NULL auto_increment,

  `name` varchar(32) collate utf8_unicode_ci NOT NULL,

  `ike_version` tinyint(3) unsigned NOT NULL default '2',

  `ike_cfg` int(10) unsigned NOT NULL,

  `local_id` varchar(64) collate utf8_unicode_ci NOT NULL,

  `remote_id` varchar(64) collate utf8_unicode_ci NOT NULL,

  `cert_policy` tinyint(3) unsigned NOT NULL default '1',

  `uniqueid` tinyint(3) unsigned NOT NULL default '0',

  `auth_method` tinyint(3) unsigned NOT NULL default '1',

  `eap_type` tinyint(3) unsigned NOT NULL default '0',

  `eap_vendor` smallint(5) unsigned NOT NULL default '0',

  `keyingtries` tinyint(3) unsigned NOT NULL default '3',

  `rekeytime` mediumint(8) unsigned NOT NULL default '7200',

  `reauthtime` mediumint(8) unsigned NOT NULL default '0',

  `jitter` mediumint(8) unsigned NOT NULL default '180',

  `overtime` mediumint(8) unsigned NOT NULL default '300',

  `mobike` tinyint(1) NOT NULL default '1',

  `dpd_delay` mediumint(8) unsigned NOT NULL default '120',

  `virtual` varchar(40) default NULL,

  `pool` varchar(32) default NULL,

  `mediation` tinyint(1) NOT NULL default '0',

  `mediated_by` int(10) unsigned NOT NULL default '0',

  `peer_id` int(10) unsigned NOT NULL default '0',

  PRIMARY KEY (`id`),

  INDEX (`name`)

) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci;

DROP TABLE IF EXISTS `peer_config_child_config`;

CREATE TABLE `peer_config_child_config` (

  `peer_cfg` int(10) unsigned NOT NULL,

  `child_cfg` int(10) unsigned NOT NULL,

  PRIMARY KEY (`peer_cfg`, `child_cfg`)

) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci;

DROP TABLE IF EXISTS `traffic_selectors`;

CREATE TABLE `traffic_selectors` (

  `id` int(10) unsigned NOT NULL auto_increment,

  `type` tinyint(3) unsigned NOT NULL default '7',

  `protocol` smallint(5) unsigned NOT NULL default '0',

  `start_addr` varbinary(16) default NULL,

  `end_addr` varbinary(16) default NULL,

  `start_port` smallint(5) unsigned NOT NULL default '0',

  `end_port` smallint(5) unsigned NOT NULL default '65535',

  PRIMARY KEY (`id`)

) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci;

DROP TABLE IF EXISTS certificates;

CREATE TABLE certificates (

  `id` int(10) unsigned NOT NULL auto_increment,

  `type` tinyint(3) unsigned NOT NULL,

  `keytype` tinyint(3) unsigned NOT NULL,

  `data` BLOB NOT NULL,

  PRIMARY KEY (`id`)

) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci;

DROP TABLE IF EXISTS certificate_identity;

CREATE TABLE certificate_identity (

  `certificate` int(10) unsigned NOT NULL,

  `identity` int(10) unsigned NOT NULL,

  PRIMARY KEY (`certificate`, `identity`)

) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci;

DROP TABLE IF EXISTS private_keys;

CREATE TABLE private_keys (

  `id` int(10) unsigned NOT NULL auto_increment,

  `type` tinyint(3) unsigned NOT NULL,

  `data` BLOB NOT NULL,

  PRIMARY KEY  (`id`)

) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci;

DROP TABLE IF EXISTS private_key_identity;

CREATE TABLE private_key_identity (

  `private_key` int(10) unsigned NOT NULL,

  `identity` int(10) unsigned NOT NULL,

  PRIMARY KEY (`private_key`, `identity`)

) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci;

DROP TABLE IF EXISTS shared_secrets;

CREATE TABLE shared_secrets (

  `id` int(10) unsigned NOT NULL auto_increment,

  `type` tinyint(3) unsigned NOT NULL,

  `data` varbinary(256) NOT NULL,

  PRIMARY KEY (`id`)

) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci;

DROP TABLE IF EXISTS shared_secret_identity;

CREATE TABLE shared_secret_identity (

  `shared_secret` int(10) unsigned NOT NULL,

  `identity` int(10) unsigned NOT NULL,

  PRIMARY KEY (`shared_secret`, `identity`)

) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci;

DROP TABLE IF EXISTS certificate_authorities;

CREATE TABLE certificate_authorities (

  `id` int(10) unsigned NOT NULL auto_increment,

  `certificate` int(10) unsigned NOT NULL,

  PRIMARY KEY (`id`)

) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci;

DROP TABLE IF EXISTS certificate_distribution_points;

CREATE TABLE certificate_distribution_points (

  `id` int(10) unsigned NOT NULL auto_increment,

  `ca` int(10) unsigned NOT NULL,

  `type` tinyint(3) unsigned NOT NULL,

  `uri` varchar(256) NOT NULL,

  PRIMARY KEY (`id`)

) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci;

DROP TABLE IF EXISTS pools;

CREATE TABLE pools (

  `id` int(10) unsigned NOT NULL auto_increment,

  `name` varchar(32) NOT NULL,

  `start` varbinary(16) NOT NULL,

  `end` varbinary(16) NOT NULL,

  `timeout` int(10) unsigned NOT NULL,

  PRIMARY KEY (`id`),

  UNIQUE (`name`)

) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci;

DROP TABLE IF EXISTS addresses;

CREATE TABLE addresses (

  `id` int(10) unsigned NOT NULL auto_increment,

  `pool` int(10) unsigned NOT NULL,

  `address` varbinary(16) NOT NULL,

  `identity` int(10) unsigned NOT NULL DEFAULT 0,

  `acquired` int(10) unsigned NOT NULL DEFAULT 0,

  `released` int(10) unsigned NOT NULL DEFAULT 1,

  PRIMARY KEY (`id`),

  INDEX (`pool`),

  INDEX (`identity`),

  INDEX (`address`)

) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci;

DROP TABLE IF EXISTS leases;

CREATE TABLE leases (

  `id` int(10) unsigned NOT NULL auto_increment,

  `address` int(10) unsigned NOT NULL,

  `identity` int(10) unsigned NOT NULL,

  `acquired` int(10) unsigned NOT NULL,

  `released` int(10) unsigned DEFAULT NULL,

  PRIMARY KEY (`id`)

) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci;

DROP TABLE IF EXISTS attribute_pools;

CREATE TABLE attribute_pools (

  `id` int(10) unsigned NOT NULL auto_increment,

  `name` varchar(32) NOT NULL,

  PRIMARY KEY (`id`)

) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci;

DROP TABLE IF EXISTS attributes;

CREATE TABLE attributes (

  `id` int(10) unsigned NOT NULL auto_increment,

  `identity` int(10) unsigned NOT NULL default '0',

  `pool` int(10) unsigned NOT NULL default '0',

  `type` int(10) unsigned NOT NULL,

  `value` varbinary(16) NOT NULL,

  PRIMARY KEY (`id`),

  INDEX (`identity`),

  INDEX (`pool`)

) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci;

DROP TABLE IF EXISTS ike_sas;

CREATE TABLE ike_sas (

  `local_spi` varbinary(8) NOT NULL,

  `remote_spi` varbinary(8) NOT NULL,

  `id` int(10) unsigned NOT NULL,

  `initiator` tinyint(1) NOT NULL,

  `local_id_type` tinyint(3) NOT NULL,

  `local_id_data` varbinary(64) DEFAULT NULL,

  `remote_id_type` tinyint(3) NOT NULL,

  `remote_id_data` varbinary(64) DEFAULT NULL,

  `host_family` tinyint(3) NOT NULL,

  `local_host_data` varbinary(16) NOT NULL,

  `remote_host_data` varbinary(16) NOT NULL,

  `lastuse` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

  PRIMARY KEY (`local_spi`)

) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci;

DROP TABLE IF EXISTS logs;

CREATE TABLE logs (

  `id` int(10) unsigned NOT NULL auto_increment,

  `local_spi` varbinary(8) NOT NULL,

  `signal` tinyint(3) NOT NULL,

  `level` tinyint(3) NOT NULL,

  `msg` varchar(256) NOT NULL,

  `time` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,

  PRIMARY KEY (`id`)

) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci;

