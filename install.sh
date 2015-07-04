#!/bin/bash
# simpleText v1.0
# install script.
##################

version=1.0
title="simpleText"
log_facility="local0"

if [ "$EUID" -ne 0 ]
then
	echo "[-] Run as root to Install"
	exit
fi

make > /dev/null

cp -afr resources/* /etc/simpleText.d/
cp -f simpleText /usr/bin/simpleText
cp -f resources/simpleText.service /etc/systemd/system/simpleText.service

chmod 600 /etc/simpleText.d/simpleText.cfg

touch /var/log/simpleText.log

make clean > /dev/null

echo "[*] $title v$version installed succesfully.."
echo "    configure your syslog service to"
echo "    to listen on facility '$log_facility'"
echo "    or enter '# journalctl -t $title' to view logs"
echo " enter '# systemctl enable simpleText'"
echo " to run $title on startup"
