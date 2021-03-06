# BitStreamVPN

This is an IKEv2/IPsec VPN service uses that certificate-based authentication.

Motivation: I wanted to learn Spring Boot and Docker. Also, it is no fun trying to choose a VPN service (https://arstechnica.com/information-technology/2016/06/aiming-for-anonymity-ars-assesses-the-state-of-vpns-in-2016/). I'm not aware of any VPN providers that offer certificate-based authentication for IKEv2/IPsec.

## Architecture
There are five Docker containers:
- bitcoin
    - There are shell scripts that are triggered on blocknotify and walletnotify. These make calls to the webapp's updatePayment and updateConfirmations actions.
- db
    - There are two MySQL databases in this container - one that is primarily used by strongSwan, and the other that is primarily used by the webapp.
- strongswan
    - strongSwan uses the MySQL plugin for its configuration. There is no ipsec.conf or swanctl.conf.
    - There are iptables that are inserted when a client brings up the connection. 
        - An `iptables -t nat` rule is inserted so that traffic is forwarded through
        - Two `iptables -t mangle` rules are inserted, these are used to get the bandwidth counts.
    - A cron job is used to make calls to write the new bandwidth data to the database; and to clean up any connections
- webapp
    - This is a Spring Boot app which serves as the front-end. Thymeleaf is used for templating, and Gradle is used for building. Bootstrap is used for the UI.
    - The webapp has the Subscription and Payment logic, and is also responsible for issuing certificates based on the user's CSR.
- modsecurity

## Requirements
You will need Java, Gradle, and Docker installed.

## Set up keystore
`sudo apt-get install strongswan` (need this for ipsec pki. will move commands to use openssl later)

`cd ipsec-pki ; bash -x buildKeystore.sh`    

## Build webapp
`./gradlew build buildDocker`

## Run (this will build the other images)
- `docker-compose up -d`

## Make Payment (this uses the regtest network)

### Connect bitcoin wallet
`bitcoin-qt -datadir=/home/ram/bob-datadir -port=19444 -rpcport=19332 -rpcuser=bob -rpcpassword=bobpass -connect=172.20.0.1:18333 -regtest -server -listen -debug`

### Generate block
`bitcoin-cli -regtest -rpcport=19332 -rpcuser=bob -rpcpassword=bobpass generate 1`
