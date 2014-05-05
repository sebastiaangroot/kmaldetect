#!/bin/bash

if [ `id -u` -ne 0 ]; then
	echo "This command needs to be run as root."
	exit 1
fi

SRCDIR=/home/maldetect/
DESTDIR=/home/sebastiaan/git/kmaldetect/traces/
DAY=`date | cut -d " " -f 2-3`
FILE=`ls -l $SRCDIR | grep "$DAY" | tr -s " " | rev | cut -d " " -f 1 | rev`

if [ -z $FILE ]; then
	echo "File not found"
	exit 1
fi

mv $SRCDIR$FILE $DESTDIR
chown sebastiaan:sebastiaan $DESTDIR/$FILE
