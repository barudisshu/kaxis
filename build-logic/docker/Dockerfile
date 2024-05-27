# usage: docker build . -t <tag> service/Dockerfile

FROM openjdk:17-slim

WORKDIR /opt/aiot

COPY ./build/kaxis-*-SNAPSHOT.jar /opt/aiot/kaxis.jar
COPY ./docker/logback.xml /opt/aiot/logback.xml
COPY ./docker/start.sh /opt/aiot/start.sh
COPY ./docker/application.conf /opt/aiot/application.conf

ENV JAVA_ARGS "-Xms512m -Xmx512m"
ENV JVM_PROPS "-Dlogging.config=file:///opt/aiot/logback.xml \
               -Dconfig.file=/opt/aiot/application.conf \
               -Djava.util.prefs.systemRoot=/opt/aiot/.java \
               -Djava.util.prefs.userRoot=/opt/aiot/.java/.userPrefs \
               -XX:ErrorFile=/var/log/jvm/aiot_hs_err_%p.log \
               -XX:+HeapDumpOnOutOfMemoryError \
               -XX:HeapDumpPath=/var/log/jvm/aiot_heapdump_%p.hprof"

RUN chmod +x /opt/aiot/start.sh && \
    echo "veil: true" > /opt/aiot/application-veil.yaml && \
    echo "alias ll=\"ls -alF --color\"" ~/.bashrc

CMD ["/bin/bash", "/opt/aiot/start.sh"]
