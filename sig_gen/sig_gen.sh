#!/bin/bash

function usage
{
	echo "Usage: $0 -o <outfile> <executable> [arguments]"
	exit
}

function syscall_to_number
{
	case "$1" in
	'time')
		return 0
	'stime')
		return 1
	'gettimeofday')
		return 2
	'settimeofday')
		return 3
	'')
		return 4
	esac
}

OUTFILE=
STRACE_ARGS=
SYSCALLS=
SYS_NUMSEQ=

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

#Generate the strace, strip everything but the syscall name and recode the syscall names to a sequence of syscall numbers
strace $STRACE_ARGS 2> $OUTFILE.strace
cat $OUTFILE.strace | cut -d "(" -f 1 > $OUTFILE.tmp
rm $OUTFILE.strace

SYSCALLS=(`cat $OUTFILE.tmp`)

for (( i=0; i < ${#SYSCALLS[@]}; i++))
do
	echo ${SYSCALLS[$i]}
done


