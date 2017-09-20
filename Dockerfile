FROM openjdk:8u141-jdk
COPY target/gs-serving-web-content-0.1.0.jar /usr/src/myapp/
COPY target/server.keystore /usr/src/myapp
WORKDIR /usr/src/myapp
ENTRYPOINT ["java", "-jar", "-Dkeystore.location=/usr/src/myapp/server.keystore", "gs-serving-web-content-0.1.0.jar"]

