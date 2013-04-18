#ifndef libdummy_h__
#define libdummy_h__

struct com_info
{
	unsigned char type;
	unsigned short pid_1;
	unsigned short pid_2;
};

void lib_register_fnct(struct com_info (* funct_p)(), void (* funct2_p)(struct com_info com));
extern void lib_entry(void);

#endif
