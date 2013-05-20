#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kthread.h>
#include "nl_iface.h"
#include "kmaldetect.h"

static int __init mod_start(void)
{
	maldetect_nl_init();

	printk(KERN_INFO "[test_mod] Initiated\n");

	return 0;
}

static void __exit mod_end(void)
{
	maldetect_nl_close();

	printk(KERN_INFO "[test_mod] Stopped\n");
}

module_init(mod_start);
module_exit(mod_end);
