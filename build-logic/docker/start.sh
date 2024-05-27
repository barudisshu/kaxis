#!/bin/sh
if [ "$DEBUG_MODE" = "true" ]; then
    JVM_PROPS="$JVM_PROPS -Dlogging.config=file:///opt/aiot/logback-debug.xml"
fi
exec java $JAVA_ARGS $JVM_PROPS -jar /opt/aiot/kaxis.jar
