FROM bitnami/keycloak:21.1.2

USER root

ENV LANG C.UTF-8
ENV LC_ALL C.UTF-8
ENV JAVA_TOOL_OPTIONS -Dfile.encoding=UTF-8

RUN apt update && \
    apt install fontconfig -y --allow-change-held-packages && \
    apt install --fix-broken -y --allow-change-held-packages

RUN rm -f /opt/bitnami/keycloak/lib/lib/main/org.keycloak.keycloak-model-jpa-21.1.2.jar
COPY keycloak-model-jpa-21.1.2.jar /opt/bitnami/keycloak/lib/lib/main/org.keycloak.keycloak-model-jpa-21.1.2.jar
RUN rm -f /opt/bitnami/keycloak/lib/lib/main/org.keycloak.keycloak-server-spi-21.1.2.jar
COPY keycloak-server-spi-21.1.2.jar /opt/bitnami/keycloak/lib/lib/main/org.keycloak.keycloak-server-spi-21.1.2.jar
RUN rm -f /opt/bitnami/keycloak/lib/lib/main/org.keycloak.keycloak-server-spi-private-21.1.2.jar
COPY keycloak-server-spi-private-21.1.2.jar /opt/bitnami/keycloak/lib/lib/main/org.keycloak.keycloak-server-spi-private-21.1.2.jar
RUN rm -f /opt/bitnami/keycloak/lib/lib/main/org.keycloak.keycloak-services-21.1.2.jar
COPY keycloak-services-21.1.2.jar /opt/bitnami/keycloak/lib/lib/main/org.keycloak.keycloak-services-21.1.2.jar
RUN rm -f /opt/bitnami/keycloak/lib/lib/main/org.keycloak.keycloak-quarkus-server-21.1.2.jar
COPY keycloak-quarkus-server-21.1.2.jar /opt/bitnami/keycloak/lib/lib/main/org.keycloak.keycloak-quarkus-server-21.1.2.jar
RUN rm -f /opt/bitnami/keycloak/lib/lib/main/org.keycloak.keycloak-themes-21.1.2.jar
COPY keycloak-themes-21.1.2.jar /opt/bitnami/keycloak/lib/lib/main/org.keycloak.keycloak-themes-21.1.2.jar
RUN rm -f /opt/bitnami/keycloak/lib/lib/main/org.keycloak.keycloak-model-legacy-private-21.1.2.jar
COPY keycloak-model-legacy-private-21.1.2.jar /opt/bitnami/keycloak/lib/lib/main/org.keycloak.keycloak-model-legacy-private-21.1.2.jar


USER 1001
