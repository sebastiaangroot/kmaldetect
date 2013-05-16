#!/bin/bash

function usage()
{
	echo "Usage: $0 -o <outfile> <executable> [arguments]"
	exit
}

OUTFILE=
STRACE_ARGS=

#Argument handling (required option -o <outfile> first, then all remaining arguments as input for strace)
while getopts ":ho:" opt
do
	case $opt in
		o)
			OUTFILE=$OPTARG
			shift $((OPTIND-1))
			;;
		h)
			usage
			;;
		\?)
			usage
			;;
		:)
			usage
			;;
	esac
done

if [ $# -eq 0 ]
then
	usage
fi

while [ $# -ne 0 ]
do
	if [ -z "$STRACE_ARGS" ]
	then
		STRACE_ARGS="$1"
	else
		STRACE_ARGS="$STRACE_ARGS $1"
	fi

	shift
done

strace $STRACE_ARGS 2> $OUTFILE.strace

cat $OUTFILE.strace | cut -d "(" -f 1 > $OUTFILE.tmp

rm $OUTFILE.strace


