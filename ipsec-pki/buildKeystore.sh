#!/bin/bash

ipsec pki --gen > caKey.der
ipsec pki --self --in caKey.der --dn "C=US, O=test, CN=testCA" --ca > caCert.der
ipsec pki --gen > peerKey.der
ipsec pki --pub --in peerKey.der | ipsec pki --issue --cacert caCert.der --cakey caKey.der \
                                             --dn "C=US, O=test, CN=peer2" > peerCert.der
openssl pkey -inform DER -in caKey.der -outform PEM -out caKey.pem
openssl x509 -inform DER -in caCert.der -outform PEM -out caCert.pem
openssl pkey -inform DER -in peerKey.der -outform PEM -out peerKey.pem
openssl x509 -inform DER -in peerCert.der -outform PEM -out peerCert.pem

# The (ca|peer1|peer2)(Key|PubKey|Cert).(pem|der) files were created using the `ipsec pki` commands found on strongswan.org
# and openssl extract the pubkey; and to convert der to pem

# create a pkcs12 bundle of the CA cert & key
openssl pkcs12 -export -out javaca.p12 -name javaalias -in caCert.pem -inkey caKey.pem -CAfile caCert.pem -caname root -password pass:testing

# create a java keystore of pkcs12 CA bundle
keytool -importkeystore -deststorepass changeit -destkeypass changeit -destkeystore server.keystore -srckeystore javaca.p12 -srcstoretype PKCS12 -srcstorepass testing -alias javaalias

# list contents
#keytool -list -v -keystore server.keystore

# create a pkcs12 bundler of the server cert & key
openssl pkcs12 -export -out javaserver.p12 -name javaserveralias -in peerCert.pem -inkey peerKey.pem -password pass:testing

# import pkcs12 server bundle into keystore
keytool -importkeystore -deststorepass changeit -destkeypass changeit -destkeystore server.keystore -srckeystore javaserver.p12 -srcstoretype PKCS12 -srcstorepass testing -alias javaserveralias
