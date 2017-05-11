FROM	docker-registry.lab.nordigy.ru:443/opsimage-scratch

ENV	DJANGO_SETTINGS_MODULE=sipa.settings STATSD_HOST=127.0.0.1 STATSD_PORT=8125 WORKERS=8

ADD     files/requirement.txt   /root/pip/
ADD     files/krb5.conf         /etc/krb5.conf
ADD	files/moriot		/etc/pam.d/

RUN	yum install -y \
		krb5-workstation pam_krb5 \
		python27 python27-python python27-python-setuptools \
		python27-python-devel gcc gcc-c++ graphviz-devel openldap-devel libxml2-devel libxslt-devel swig openssl-devel \
		freetype-devel libpng-devel mysql-devel mysql-client cairo cairo-devel dvipng \
		libffi libffi-devel libjpeg-turbo libjpeg-turbo-devel turbojpeg turbojpeg-devel

RUN 	scl enable python27 "easy_install pip" && \
	scl enable python27 "pip install --upgrade pip"
RUN	scl enable python27 "pip install -r /root/pip/requirement.txt"
RUN	scl enable python27 "pip install reportlab"

RUN	yum erase -y gcc gcc-c++ graphviz-devel openldap-devel swig openssl-devel python27-python-devel && \
	yum clean all

ADD     files/ui/               /opt/ui/

WORKDIR	/opt/ui

CMD	scl enable python27 "gunicorn -k gevent --statsd-host ${STATSD_HOST}:${STATSD_PORT} --statsd-prefix ui --error-logfile - --log-file - --workers=${WORKERS} --bind=0.0.0.0:80 --bind=0.0.0.0:8080 --timeout=3600 sipa.wsgi:application"
