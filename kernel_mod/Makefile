obj-m := newsyslog.o
newsyslog-objs := syslogger.o testfunct.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
