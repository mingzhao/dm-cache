obj-m += dmcache.o
dmcache-objs := dm-cache.o dm-dedup2.o


all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
