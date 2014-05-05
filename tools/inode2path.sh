#!/bin/bash

if [ $# -ne 1 ]; then
	echo "Usage: $0 <inode>"
	exit 1
fi

if [ `id -u` -ne 0 ]; then
	SUDO="sudo"
else
	SUDO=""
fi

$SUDO find / -inum $1 -ls 2> /dev/null | tr -s " " | rev | cut -d " " -f 1 | rev
