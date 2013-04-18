#include <stdio.h>
#include "libdummy.h"

//lib_register_fnct will be used to pass the function pointers for the thread-safe read and write functions in the main program. Here, the first argument is the read and the second the write function
void lib_register_fnct(struct com_info (* funct_p)(), void (* funct2_p)(struct com_info com))
{
	funct2_p(funct_p());
}

//This function gets called by the pthread_create function in the main program, spawning the module as seperate thread
void lib_entry(void)
{
}
