#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include <asm/types.h>

#define READ		0
#define WRITE		1

typedef unsigned long sector_t;

struct io_req {
        unsigned int sector;
        unsigned long rw;
        unsigned int size;
	unsigned int major;
	unsigned int minor;
};

int main() {
	struct io_req req = {
		.sector = 2,
	//	.rw = READ,
		.rw = WRITE,
		.size = 512,
		.major = 8,
		.minor = 0,
	};

	int fd = open("/dev/dev_req", O_WRONLY);
	ssize_t total = write(fd, &req, sizeof(struct io_req));

	printf("%d wrote\n",total);
	
	return 0;
}
