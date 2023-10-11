FROM bitnami/keycloak:21.1.2

USER root

ENV LANG C.UTF-8
ENV LC_ALL C.UTF-8
ENV JAVA_TOOL_OPTIONS -Dfile.encoding=UTF-8

RUN apt update && \
    apt install fontconfig -y --allow-change-held-packages && \
    apt install --fix-broken -y --allow-change-held-packages

#RUN rm -f /opt/bitnami/keycloak/modules/system/layers/keycloak/org/keycloak/keycloak-model-jpa/main/keycloak-model-jpa-21.1.2.jar
#COPY keycloak-model-jpa-21.1.2.jar /opt/bitnami/keycloak/modules/system/layers/keycloak/org/keycloak/keycloak-model-jpa/main/keycloak-model-jpa-21.1.2.jar
#RUN rm -f /opt/bitnami/keycloak/modules/system/layers/keycloak/org/keycloak/keycloak-server-spi-private/main/keycloak-server-spi-21.1.2.jar
#COPY keycloak-server-spi-21.1.2.jar /opt/bitnami/keycloak/modules/system/layers/keycloak/org/keycloak/keycloak-server-spi/main/keycloak-server-spi-21.1.2.jar
#RUN rm -f /opt/bitnami/keycloak/modules/system/layers/keycloak/org/keycloak/keycloak-server-spi-private/main/keycloak-server-spi-private-21.1.2.jar
#COPY keycloak-server-spi-private-21.1.2.jar /opt/bitnami/keycloak/modules/system/layers/keycloak/org/keycloak/keycloak-server-spi-private/main/keycloak-server-spi-private-21.1.2.jar
#RUN rm -f /opt/bitnami/keycloak/modules/system/layers/keycloak/org/keycloak/keycloak-services/main/keycloak-services-21.1.2.jar
#COPY keycloak-services-21.1.2.jar /opt/bitnami/keycloak/modules/system/layers/keycloak/org/keycloak/keycloak-services/main/keycloak-services-21.1.2.jar

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

#COPY dist/* /opt/bitnami/keycloak/themes/custom/dist
#COPY dist/assets/*.css /opt/bitnami/keycloak/themes/keycloak/login/resources/img
#COPY dist/assets/*.js /opt/bitnami/keycloak/themes/keycloak/login/resources/img
#COPY dist/assets/*.svg /opt/bitnami/keycloak/themes/keycloak/login/resources/img
#COPY dist/assets/*.mp4 /opt/bitnami/keycloak/themes/keycloak/login/resources/img
#COPY dist/assets/*.png /opt/bitnami/keycloak/themes/keycloak/login/resources/img
#COPY dist/assets/*.gif /opt/bitnami/keycloak/themes/keycloak/login/resources/img
#COPY dist/assets/*.webp /opt/bitnami/keycloak/themes/keycloak/login/resources/img

COPY dist/* /opt/bitnami/keycloak/themes/mynewtheme/
COPY dist/assets/* /opt/bitnami/keycloak/themes/mynewtheme/

#COPY dist/*.ico /opt/bitnami/keycloak/themes/keycloak/login/resources/img
#COPY dist/assets/*.js /opt/jboss/keycloak/themes/keycloak/login/resources/js/

USER 1001
