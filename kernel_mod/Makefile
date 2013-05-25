obj-m := kmaldetect.o
kmaldetect-objs := kmaldetect_main.o hooks.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
