FILES=blacklist.py cfg.py wumi.py wumi.cf.deliver

default:
	cat ${MAKEFILE}

install-host:
.if !defined(HOST)
	@echo You have to call
	@echo make 'HOST=<hostname>'
.else
	rsync -v ${FILES} root@${HOST}:/etc/mail/
	ssh root@${HOST} 'svc -t /service/wumi/'
.endif

georg:
	rsync *.py ~georg/service/wumi
	cat wumi.cf > /etc/mail/wumi.cf
	cp wumi-config.py /usr/local/bin/wumi-config

pocken:
	scp *py root@$@:/etc/mail
	scp wumi.cf.deliver root@$@:/etc/mail/wumi.cf

fsme:
	scp *py root@$@:/etc/mail
	scp wumi.cf.deliver root@$@:/etc/mail/wumi.cf

schurli:
	scp *py root@$@:/etc/mail
	scp wumi.cf root@$@:/etc/mail/wumi.cf

herpes:
	scp *py root@$@:/etc/mail
	scp wumi.cf root@$@:/etc/mail/wumi.cf

influenza:
	scp *py root@$@:/etc/mail
	scp wumi.cf root@$@:/etc/mail/wumi.cf


install:
	@echo "for i in `head -1 ~/all/milterhosts`"
	@echo do rsync -v ${FILES} root@$$\i:/etc/mail/
	@echo done
	@echo proot  ~/all/milterhosts "'"svc -t /service/wumi"'"

check:
	pychecker *.py

status:
	proot ~/all/milterhosts 'tail -25 /service/wumi/log/main/current | tai64nlocal'

restartall:
	proot ~/all/milterhosts 'svc -t /service/wumi'

