FROM	docker-registry.lab.nordigy.ru:443/opsimage-scratch

ENV	SYS_CATCH_OUT=1 MALLOC_CHECK_=1

ADD	files/entry.sh /root/
ADD	files/rpms/ /root/rpms/

RUN \
	rpm -Uvh http://dl.fedoraproject.org/pub/epel/6/x86_64/epel-release-6-8.noarch.rpm && \
	yum reinstall -y centos-release && \
	yum install -y \
		gcc make gcc-c++ jemalloc jemalloc-devel dkms glibc-utils \
		flex flex-devel bison numactl numactl-devel openssl openssl-devel \
		zeromq3 zeromq3-devel \
		/root/rpms/statsd-c-client-2.0.1-1.el6.x86_64.rpm \
		/root/rpms/statsd-c-client-devel-2.0.1-1.el6.x86_64.rpm \
		/root/rpms/libosip2/libosip2-4.1.0-1.x86_64.rpm  \
		/root/rpms/libosip2/libosip2-devel-4.1.0-1.x86_64.rpm && \
	ln -s /usr/lib64/libstatsdclient.so.2.0.1 /usr/lib64/libstatsdclient.so && \
	rpm -Uvh --nodeps /root/rpms/pfring-6.0.3-1.x86_64.rpm && ldconfig

ADD	files/3rdparty/libpcap /opt/src/libpcap
WORKDIR	/opt/src/libpcap
RUN	./configure --prefix=/opt/libpcap && make && make install

ADD	files/pf_ring.conf /etc/modprobe.d/
ADD	files/capture/ /opt/capture
WORKDIR	/opt/capture

RUN	make clean && make
ENTRYPOINT	["/root/entry.sh"]
