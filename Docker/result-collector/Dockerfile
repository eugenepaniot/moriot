FROM	docker-registry.lab.nordigy.ru:443/opsimage-scratch

ADD	files/rpms/	/root/rpms/

RUN \
	rpm -Uvh http://dl.fedoraproject.org/pub/epel/6/x86_64/epel-release-6-8.noarch.rpm && \
	yum reinstall -y centos-release && \
	yum install -y \
		python27-python python27-python-setuptools \
		python27-python-devel gcc gcc-c++ && \
	yum localinstall -y \
		/root/rpms/zeromq-devel-4.1.2-1.el6.x86_64.rpm \
		/root/rpms/zeromq-4.1.2-1.el6.x86_64.rpm

RUN 	scl enable python27 "easy_install pip" && \
	scl enable python27 "pip install --verbose pyzmq psutil argparse statsd resource simplejson gevent" && \
	yum remove -y gcc gcc-c++ python27-python-devel && \
	yum clean all

ADD	files/result-collector/ /opt/result-collector/
WORKDIR	/opt/result-collector

CMD	scl enable python27 "/opt/result-collector/result-collector.py"
