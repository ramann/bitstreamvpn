FROM buildpack-deps:xenial

RUN apt-get update && apt-get install -y haveged curl libgmp-dev module-init-tools netcat iptables python-mysqldb && apt-get upgrade -y

ENV STRONGSWAN_VERSION 5.6.0
ENV GPG_KEY 948F158A4E76A27BF3D07532DF42C170B34DBA77

RUN mkdir -p /usr/src/strongswan \
	&& cd /usr/src \
	&& curl -SOL "https://download.strongswan.org/strongswan-$STRONGSWAN_VERSION.tar.gz.sig" \
	&& curl -SOL "https://download.strongswan.org/strongswan-$STRONGSWAN_VERSION.tar.gz" \
	&& export GNUPGHOME="$(mktemp -d)" \
	&& gpg --keyserver ha.pool.sks-keyservers.net --recv-keys "$GPG_KEY" \
	&& gpg --batch --verify strongswan-$STRONGSWAN_VERSION.tar.gz.sig strongswan-$STRONGSWAN_VERSION.tar.gz \
	&& tar -zxf strongswan-$STRONGSWAN_VERSION.tar.gz -C /usr/src/strongswan --strip-components 1 \
	&& cd /usr/src/strongswan \
	&& ./configure --prefix=/usr --sysconfdir=/etc \
	    --enable-aesni \
	    --enable-gcm \
	    --enable-sql \
	    --enable-mysql \
	    --enable-sqlite \
	    --enable-attr-sql \
	&& make -j \
	&& make install \
    && rm -rf "/usr/src/strongswan*" \
    && mkdir -p /usr/local/bin/ipsec

ADD strongswan.conf /etc/strongswan.conf
ADD insert.py /usr/local/bin/ipsec/insert.py
ADD update.py /usr/local/bin/ipsec/update.py
ADD get_nflog_from_peerid.py /usr/local/bin/ipsec/get_nflog_from_peerid.py
ADD delete_from_bandwidth.py /usr/local/bin/ipsec/delete_from_bandwidth.py
ADD cron.sh /usr/local/bin/ipsec/cron.sh
ADD _updown.sh /usr/local/bin/ipsec/_updown.sh

EXPOSE 4500/udp 500/udp

cmd ipsec start --nofork
