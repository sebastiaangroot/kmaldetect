#!/bin/bash

if [ $# -ne 1 ]; then
	echo "Usage: $0 <path>"
	exit 0
fi

ls -i $1
