# build phase
FROM openjdk:11 AS build
WORKDIR /build/

COPY gradlew /build/
COPY gradle /build/gradle
WORKDIR /build
RUN ./gradlew --version

# Build
COPY . .
ARG ARTIFACTORY_PRO_USER
ARG ARTIFACTORY_PRO_PASS
ARG GIT_BRANCH
ARG GIT_TAG

RUN ./gradlew --no-daemon syncJavaAgentDependencies test bootJar

RUN mv ./build/libs/workiva-spring-security-*.jar ./server.jar
RUN mv ./build/libs/javaagent/newrelic-agent-*.jar ./newrelic-agent.jar

# Generate Veracode Artifact
RUN tar czf ./java.tar.gz ./server.jar
ARG BUILD_ARTIFACTS_VERACODE=/build/java.tar.gz

# Download the RDS CA bundle and split the bundle into individual certs
RUN mkdir /rds-certs && cd /rds-certs && curl -O https://s3.amazonaws.com/rds-downloads/rds-combined-ca-bundle.pem
RUN cd /rds-certs && csplit -sz rds-combined-ca-bundle.pem '/-BEGIN CERTIFICATE-/' '{*}'

# WK builder generates Helm/CloudFormation artifacts.
FROM drydock-prod.workiva.net/workiva/wk:v1

# Production image
FROM amazoncorretto:11

# Disable Java DNS caching.
# https://github.com/Workiva/architecture/pull/189
RUN sed -i \
        -e 's/#networkaddress.cache.ttl=.*/networkaddress.cache.ttl=0/g' \
        -e 's/networkaddress.cache.negative.ttl=.*/networkaddress.cache.negative.ttl=0/g' \
        $JAVA_HOME/conf/security/java.security

ARG BUILD_ID
ENV BUILD_ID=$BUILD_ID

# package updating for aviary (should be done after BUILD_ID to bust the cache)
RUN yum update -y && \
    yum upgrade -y && \
    yum autoremove -y && \
    yum clean all

COPY --from=build /build/server.jar /opt/jars/server.jar
COPY --from=build /build/newrelic-agent.jar /opt/newrelic-agent.jar
COPY ./scripts/run-server.sh /opt/run-server.sh
RUN chmod +x /opt/run-server.sh

# Add Amazon's RDS CA bundle to java keystores
COPY --from=build /rds-certs/ /rds-certs/
RUN for CERT in /rds-certs/xx*; do keytool -import -storepass changeit -noprompt -alias awsrds$CERT -file $CERT -cacerts ; done

USER nobody
CMD ["sh", "/opt/run-server.sh"]

EXPOSE 8080
