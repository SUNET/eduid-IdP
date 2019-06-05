FROM docker.sunet.se/eduid/python3env:slim

MAINTAINER eduid-dev <eduid-dev@SEGATE.SUNET.SE>

VOLUME ["/opt/eduid/eduid-idp/etc", "/opt/eduid/src", "/var/log/eduid"]

ADD docker/setup.sh /opt/eduid/setup.sh
RUN /opt/eduid/setup.sh

ADD docker/start.sh /start.sh

# Add Dockerfile to the container as documentation
ADD Dockerfile /Dockerfile

# revision.txt is dynamically updated by the CI for every build,
# to ensure build.sh is executed every time
ADD docker/revision.txt /revision.txt

ADD . /src/eduid-IdP

ADD docker/build.sh /opt/eduid/build.sh
RUN /opt/eduid/build.sh

WORKDIR /

EXPOSE 8080

HEALTHCHECK --interval=10s CMD curl http://localhost:8080/healthy | grep -q STATUS_OK

CMD ["bash", "/start.sh"]
