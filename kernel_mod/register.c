unsigned long **sys_call_table;

extern long sys_mkdir(const char __user *pathname, int mode);
long (*ref_sys_mkdir)(const char __user *pathname, int mode);
long (new_sys_mkdir)(const char __user *pathname, int mode)
{
	long retval;
	retval = ref_sys_mkdir(pathname, mode);
	printk(KERN_INFO "hook: [pid: %i ppid: %i] mkdir(%s, %i) = %ld\n", current->pid, current->parent->pid, pathname, mode, retval);
	return retval;
}

//Check if the cr0 write-protect bit is set. If not, page write-protection is already disabled. If so, bitwise-AND bit 16 to zero and set it to cr0
static void disable_page_protection(void)
{
	unsigned long value;
	asm volatile("mov %%cr0, %0" : "=r"(value));
	if (!(value & 0x00010000))
	{
		return;
	}

	asm volatile("mov %0, %%cr0" : : "r" (value & ~0x00010000));
}

//Check if cr0 write-protect bit is set. If so, page write-protection is already enabled. If not, bitwise-OR bit 16 to one and set it to cr0
static void enable_page_protection(void)
{
	unsigned long value;
	asm volatile("mov %%cr0, %0" : "=r" (value));

	if ((value & 0x00010000))
	{
		return;
	}

	asm volatile("mov %0, %%cr0" : : "r" (value | 0x00010000));
}

static int __init mod_start(void)
{
	printk(KERN_INFO "mkdirlogger loaded\n");

	testlogfunct();

	if(!(sys_call_table = acquire_sys_call_table()))
	{
		return -1;
	}

	disable_page_protection();

	ref_sys_mkdir = &sys_mkdir;//(void *)sys_call_table[__NR_mkdir];
	sys_call_table[__NR_mkdir] = (unsigned long *)new_sys_mkdir;
	
	enable_page_protection();
	return 0;
}

static void unregister_hooks(unsigned long **sys_call_table)
{
	if (!sys_call_table)
	{
		return;
	}

	disable_page_protection();



	enable_page_protection();
}

static void __exit mod_end(void)
{
	printk(KERN_INFO "mkdirlogger exiting\n");

	if(!sys_call_table)
	{
		return;
	}

	disable_page_protection();
	
	sys_call_table[__NR_mkdir] = (unsigned long *)ref_sys_mkdir;
	
	enable_page_protection();
}

module_init(mod_start);
module_exit(mod_end);
