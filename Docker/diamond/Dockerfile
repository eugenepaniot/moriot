FROM	docker-registry.lab.nordigy.ru:443/opsimage-scratch

RUN \
	rpm -Uvh http://dl.fedoraproject.org/pub/epel/6/x86_64/epel-release-6-8.noarch.rpm && \
	yum reinstall -y centos-release && \
	yum install -y diamond python-pip MySQL-python lsof && \
	pip install --no-cache-dir python-statsd

ADD	files/diamond/ /etc/diamond/

CMD	/usr/bin/diamond -f --skip-change-user --skip-fork
