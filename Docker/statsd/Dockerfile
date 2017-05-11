# TO_BUILD: docker build --rm --pull=true -t moriot-statsd .
# TO_RUN: docker run --name moriot-statsd -v /dev/log:/dev/log --net="host" -d docker-registry.ops.ringcentral.com:443/sysops/moriot-statsd:latest

FROM	docker-registry.lab.nordigy.ru:443/opsimage-scratch

ADD	files/statsd /opt/statsd/
ADD	files/config.js /opt/statsd/

RUN \
	rpm -Uvh http://dl.fedoraproject.org/pub/epel/6/x86_64/epel-release-6-8.noarch.rpm && \
	yum reinstall -y centos-release && \
	yum install -y nodejs http-parser libuv

EXPOSE	8125

WORKDIR	/opt/statsd/

CMD 	node stats.js config.js
