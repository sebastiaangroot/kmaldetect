#ifndef LIBIFACE_H
#define LIBIFACE_H

struct com_info
{
	unsigned char type;
	unsigned short pid_1;
	unsigned short pid_2;
};

extern struct com_info libiface_read(void);
extern void libiface_write(struct com_info com);
//Placeholder

#endif
