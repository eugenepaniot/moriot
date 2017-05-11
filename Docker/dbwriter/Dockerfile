FROM	docker-registry.lab.nordigy.ru:443/opsimage-scratch

RUN \
	yum install -y \
		python27-python python27-python-setuptools \
		python27-python-devel gcc gcc-c++  \
		mysql-devel mysql-client \
		zeromq3 zeromq3-devel openssl openssl-devel

RUN 	scl enable python27 "easy_install pip" && \
	scl enable python27 "pip install pyzmq psutil argparse statsd resource simplejson gevent" && \
	scl enable python27 "pip install MySQL-python mysqlclient" 

ADD	files/dbwriter/ /opt/dbwriter/
WORKDIR	/opt/dbwriter
