FROM openjdk:12.0.1-jdk
COPY target/webapp-0.1.0.jar /usr/src/myapp/
COPY target/server.keystore /usr/src/myapp
WORKDIR /usr/src/myapp
