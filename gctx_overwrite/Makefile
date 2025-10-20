obj-m += gctx_overwrite.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

insmod: all
	sudo insmod gctx_overwrite.ko

log:
	tail -f /var/log/messages
