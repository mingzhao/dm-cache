obj-m += dmcache.o
dmcache-objs := dm-cache.o dm-container.o lru.o

all:
	make -C /lib/modules/`uname -r`/build M=$(PWD) modules

install:
	make -C /lib/modules/`uname -r`/build M=$(PWD) modules

clean:
	make -C /lib/modules/`uname -r`/build M=$(PWD) clean
