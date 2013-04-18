#include <stdio.h>
#include "libiface.h"

struct com_info libiface_read(void)
{
	printf("libiface_read called by a module\n");
	struct com_info com;
	com.type = 0x0;
	com.pid_1 = 52;
	com.pid_2 = 25;
	return com;
}

void libiface_write(struct com_info com)
{
	printf("libiface_write called by a module\n");
	switch (com.type)
	{
		case 0x0:
			printf("PID: %u and %u communicate using TCP sockets.\n", com.pid_1, com.pid_2);
			break;
		case 0x1:
			printf("PID: %u and %u communicate using UNIX pipes.\n", com.pid_1, com.pid_2);
			break;
	}
}
