FROM owasp/modsecurity-crs:v3.0

ENV PARANOIA 4
#RUN yum install -y mod_ssl
RUN sed -i -e 's/SecDefaultAction "phase:1,log,auditlog,pass"/#SecDefaultAction "phase:1,log,auditlog,pass"/g' /etc/modsecurity.d/owasp-crs/crs-setup.conf
RUN sed -i -e 's/SecDefaultAction "phase:2,log,auditlog,pass"/#SecDefaultAction "phase:2,log,auditlog,pass"/g' /etc/modsecurity.d/owasp-crs/crs-setup.conf
RUN sed -i -e 's/# SecDefaultAction "phase:1,log,auditlog,deny,status:403"/SecDefaultAction "phase:1,log,auditlog,deny,status:403"/g' /etc/modsecurity.d/owasp-crs/crs-setup.conf
RUN sed -i -e 's/# SecDefaultAction "phase:2,log,auditlog,deny,status:403"/SecDefaultAction "phase:2,log,auditlog,deny,status:403"/g' /etc/modsecurity.d/owasp-crs/crs-setup.conf
#RUN sed -i -e 's/SSLCertificateFile \/etc\/pki\/tls\/certs\/localhost.crt/SSLCertificateFile \/etc\/letsencrypt\/live\/bitstreamvpn.com\/fullchain.pem/g' /etc/httpd/conf.d/ssl.conf
#RUN sed -i -e 's/SSLCertificateKeyFile \/etc\/pki\/tls\/private\/localhost.key/SSLCertificateKeyFile \/etc\/letsencrypt\/live\/bitstreamvpn.com\/privkey.pem"/g'
#RUN sed -i -e 's/#ServerName www.example.com:443/ServerName bitstreamvpn.com/g' /etc/httpd/conf.d/ssl.conf

COPY RESPONSE-999-EXCLUSION-RULES-AFTER-CRS.conf /etc/modsecurity.d/owasp-crs/rules/
COPY REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf /etc/modsecurity.d/owasp-crs/rules/
COPY httpd.conf /usr/local/apache2/conf/httpd.conf

