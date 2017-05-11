FROM	docker-registry.lab.nordigy.ru:443/opsimage-scratch

ADD     files/rpms/ /root/rpms/
RUN \	
	yum localinstall -y \
		/root/rpms/redis-3.0.3-1.el6.remi.x86_64.rpm

ADD	files/redis.conf /etc/redis/

EXPOSE	6379

CMD 	["redis-server", "/etc/redis/redis.conf"]
