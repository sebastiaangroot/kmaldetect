obj-m := kmaldetect.o
kmaldetect-objs := kmaldetect_main.o hooks.o nl_iface.o utils.o
EXTRA_CFLAGS=-I$(PWD)/include

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
