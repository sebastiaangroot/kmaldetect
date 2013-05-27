obj-m := kmaldetect.o
kmaldetect-objs := kmaldetect_main.o hooks.o netlink/nl_iface.o utils.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
