
--
-- Name: users; Type: TABLE; Schema: public; Owner: test1
--
drop table if exists payment;
drop table if exists certificate;
drop table if exists subscription;
drop table if exists users;

CREATE TABLE users (
    username varchar(30) NOT NULL primary key,
    password varchar(64) NOT NULL,
    salt varchar(16) NOT NULL
);

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
    csr_text varchar(4096) NOT NULL,
    signed boolean NOT NULL,
    cert_text varchar(4096),
    revoked boolean,
    serial bigint,
    subscription integer unsigned NOT NULL,
    date_created timestamp NOT NULL,
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
    unique (receiving_address),
    FOREIGN KEY (subscription) REFERENCES subscription(id)
);


