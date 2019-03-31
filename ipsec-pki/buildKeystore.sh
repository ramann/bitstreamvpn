#!/bin/bash

mkdir -p ca/signing-ca/db crl certs
touch ca/signing-ca/private
chmod 700 ca/signing-ca/private
cp /dev/null ca/signing-ca/db/signing-ca.db
cp /dev/null ca/signing-ca/db/signing-ca.db.attr
echo 01 > ca/signing-ca/db/signing-ca.crt.srl
echo 01 > ca/signing-ca/db/signing-ca.crl.srl

openssl genpkey -algorithm RSA -out ca_key.pem -pkeyopt rsa_keygen_bits:2048
openssl genpkey -algorithm RSA -out vpn_server_key.pem -pkeyopt rsa_keygen_bits:2048
openssl req -new -config etc/signing-ca.conf -out ca/signing-ca.csr -key ca_key.pem
openssl ca -selfsign -config etc/signing-ca.conf -in ca/signing-ca.csr -out ca/signing-ca.crt -keyfile ca_key.pem -extensions signing_ca_ext
openssl req -new -config etc/vpn_server.conf -out certs/vpn_server.csr -key vpn_server_key.pem
openssl ca -config etc/signing-ca.conf -in certs/vpn_server.csr -out certs/vpn_server.crt -keyfile ca_key.pem

#pki --gen > caKey.der
#pki --self --in caKey.der --dn "C=US, O=test, CN=testCA" --ca > caCert.der
#pki --gen > peerKey.der
#pki --pub --in peerKey.der | pki --issue --cacert caCert.der --cakey caKey.der \
#          --dn "C=US, O=test, CN=peer2" --san 104.248.14.89 > peerCert.der
#openssl pkey -inform DER -in caKey.der -outform PEM -out caKey.pem
#openssl x509 -inform DER -in caCert.der -outform PEM -out caCert.pem
#openssl pkey -inform DER -in peerKey.der -outform PEM -out peerKey.pem
#openssl x509 -inform DER -in peerCert.der -outform PEM -out peerCert.pem

# The (ca|peer1|peer2)(Key|PubKey|Cert).(pem|der) files were created using the `ipsec pki` commands found on strongswan.org
# and openssl extract the pubkey; and to convert der to pem

# create a pkcs12 bundle of the CA cert & key
openssl pkcs12 -export -out javaca.p12 -name javaalias -in ca/signing-ca.crt -inkey ca_key.pem -CAfile ca/signing-ca.crt -caname root -password pass:testing

# create a java keystore of pkcs12 CA bundle
keytool -importkeystore -deststorepass changeit -destkeypass changeit -destkeystore server.keystore -srckeystore javaca.p12 -srcstoretype PKCS12 -srcstorepass testing -alias javaalias

# list contents
#keytool -list -v -keystore server.keystore

# create a pkcs12 bundler of the server cert & key
openssl pkcs12 -export -out javaserver.p12 -name javaserveralias -in certs/vpn_server.crt -inkey vpn_server_key.pem -password pass:testing

# import pkcs12 server bundle into keystore
keytool -importkeystore -deststorepass changeit -destkeypass changeit -destkeystore server.keystore -srckeystore javaserver.p12 -srcstoretype PKCS12 -srcstorepass testing -alias javaserveralias
