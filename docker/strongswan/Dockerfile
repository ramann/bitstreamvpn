FROM ubuntu:16.04
#FROM buildpack-deps:xenial

RUN apt-get update && apt-get install -y apt-utils rsyslog build-essential haveged curl libgmp-dev module-init-tools netcat iptables python-mysqldb cron nano tcpdump libmysqlclient-dev && apt-get upgrade -y

ENV STRONGSWAN_VERSION 5.6.0
ENV GPG_KEY 948F158A4E76A27BF3D07532DF42C170B34DBA77

RUN mkdir -p /usr/src/strongswan \
	&& cd /usr/src \
	&& curl -SOL "https://download.strongswan.org/strongswan-$STRONGSWAN_VERSION.tar.gz.sig" \
	&& curl -SOL "https://download.strongswan.org/strongswan-$STRONGSWAN_VERSION.tar.gz" \
	&& export GNUPGHOME="$(mktemp -d)" \
	&& gpg --keyserver pool.sks-keyservers.net --recv-keys "$GPG_KEY" \
	&& gpg --batch --verify strongswan-$STRONGSWAN_VERSION.tar.gz.sig strongswan-$STRONGSWAN_VERSION.tar.gz \
	&& tar -zxf strongswan-$STRONGSWAN_VERSION.tar.gz -C /usr/src/strongswan --strip-components 1 \
	&& cd /usr/src/strongswan \
	&& ./configure --prefix=/usr --sysconfdir=/etc \
	    --enable-aesni \
	    --enable-gcm \
	    --enable-sql \
	    --enable-mysql \
	    --enable-attr-sql \
	&& make -j \
	&& make install \
    && mkdir -p /usr/local/bin/ipsec \
    && echo 'PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n*/2 * * * * bash -x /usr/local/bin/ipsec/cron.sh' | crontab \
    && update-rc.d cron enable

ADD strongswan.conf /etc/strongswan.conf
ADD insert.py /usr/local/bin/ipsec/insert.py
ADD update_payment_with_bandwidth.py /usr/local/bin/ipsec/update_payment_with_bandwidth.py
ADD set_disconnected.py /usr/local/bin/ipsec/set_disconnected.py
ADD delete_from_connections.py /usr/local/bin/ipsec/delete_from_connections.py
ADD identity_exists.py /usr/local/bin/ipsec/identity_exists.py
ADD cron.sh /usr/local/bin/ipsec/cron.sh
ADD _updown.sh /usr/local/bin/ipsec/_updown.sh
ADD wait_for_db.py /usr/local/bin/ipsec/wait_for_db.py

EXPOSE 4500/udp 500/udp

CMD rsyslogd && service cron restart && python /usr/local/bin/ipsec/wait_for_db.py && ipsec start --nofork
