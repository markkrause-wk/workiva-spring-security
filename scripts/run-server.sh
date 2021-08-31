#!/bin/bash

## Blocking Process, useful for debugging image
# tail -f /dev/null

if test -n "${NEW_RELIC_LICENSE_KEY}"
then
  echo "STARTUP: Starting with New Relic reporting enabled"
  exec java -javaagent:/opt/newrelic-agent.jar -Dspring.profiles.active=deployed -jar /opt/jars/server.jar
else
  exec java -Dspring.profiles.active=deployed -jar /opt/jars/server.jar
fi
