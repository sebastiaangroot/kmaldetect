#include <linux/kernel.h>
#include <linux/module.h>

void testlogfunct(void)
{
	printk(KERN_INFO "This is from a second .c file\n");
}
