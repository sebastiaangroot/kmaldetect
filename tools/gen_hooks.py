import sys
import getopt

def usage():
	print('Usage: %s --unistd=<path> --sysarch=<path> --sysarchgen=<path> --sysgen=<path> --outfile=<path>' % sys.argv[0])
	print('\t--unistd:\tarch/<architecture>/include/asm/unistd[_xx].h')
	print('\t--sysarch:\tarch/<architecture>/include/asm/syscalls.h')
	print('\t--sysarchgen:\tinclude/asm-generic/syscalls.h')
	print('\t--sysgen:\tinclude/linux/syscalls.h')
	print('\t--outfile:\tPath where you want the new hooks.c file to be created')

def get_includes():
	output = []
	output.append('#include <asm/unistd.h>\n')
	output.append('#include <linux/syscalls.h>\n')
	output.append('#include <asm/thread_info.h>\n')
	output.append('#include "nl_iface.h"\n')
	output.append('#include "utils.h"\n')
	output.append('#include "kmaldetect.h"\n')
	output.append('\n')
	output.append('extern pid_t maldetect_userspace_pid;\n')
	output.append('\n')
	return output

def get_functpointers(con_unistd, con_sysarch, con_sysarchgen, con_sysgen):
	output = []
	for line in con_unistd:
		if line.startswith('__SYSCALL('):
			found = False
			prototype = ''
			functname = line[line.find(',') + 2:-2] #the name of the syscall function
			
			"""
			Special case: We don't hook sys_execve
			"""
			if 'sys_execve' in functname:
				continue
			
			#Now we have to scan the three syscalls.h files in order to find the proper function definition with its arguments.
			for i, line in enumerate(con_sysarch): #sysarch
				if functname + '(' in line:
					prototype = line
					while not ');' in con_sysarch[i]:
						i += 1
						prototype += ' ' + con_sysarch[i].replace('\t', '').strip()
					found = True
			if not found:
				for i, line in enumerate(con_sysarchgen):
					if functname + '(' in line:
						prototype = line
						while not ');' in con_sysarchgen[i]:
							i += 1
							prototype += ' ' + con_sysarchgen[i].replace('\t', '')
						found = True
			if not found:
				for i, line in enumerate(con_sysgen):
					if functname + '(' in line:
						prototype = line
						while not ');' in con_sysgen[i]:
							i += 1
							prototype += ' ' + con_sysgen[i].replace('\t', '')
						found = True
			if found:
				duplicate = False
				if prototype.startswith('asmlinkage'):
					prototype = prototype[11:]
				ind = prototype.find('(')
				prototype = prototype[:ind] + ')' + prototype[ind:]
				ind = prototype.find(functname)
				prototype = prototype[:ind] + '(*ref_' + prototype[ind:]
				ind = prototype.find(';')
				prototype = prototype[:ind] + ' = NULL' + prototype[ind:]
				for entry in output:
					if entry in prototype:
						duplicate = True
				if not duplicate:
					output.append(prototype.replace('\n', ''))
	return output

def get_arguments_names_only(funct):
	arglist = []
	argstring = ''
	
	args = funct[funct.find('(') + 1:funct.find(')')].split(',')
	for i, arg in enumerate(args):
		if (arg == 'void') and (len(args) == 1):
			break
		
		components = arg.split(' ')
		if components[-1] in ['char', 'short', 'int', 'long',
			'size_t', 'pid_t', 'unsigned', 'char*', 'short*', 'int*',
			'long*', 'size_t*', 'pid_t*', 'unsigned*', '*']:
			arglist.append('arg%i' % i)
		elif (components[0] == 'struct') and (len(components) <= 2):
			arglist.append('arg%i' % i)
		elif components[-1].startswith('__'):
			arglist.append('arg%i' % i)
		elif components[-1].endswith('_t'):
			arglist.append('arg%i' % i)
		else:
			arglist.append(components[-1].replace('*', ''))

	for i, arg in enumerate(arglist):
		argstring += arg
		if i < len(arglist) - 1:
			argstring += ','
	return argstring
	
def get_arguments(funct):
	arglist = []
	argstring = ''
	
	args = funct[funct.find('(') + 1:funct.find(')')].split(',')
	for i, arg in enumerate(args):
		if (arg == 'void') and (len(args) == 1):
			arglist.append('void')
			break
		
		components = arg.split(' ')
		if components[-1] in ['char', 'short', 'int', 'long',
			'size_t', 'pid_t', 'unsigned', 'char*', 'short*', 'int*',
			'long*', 'size_t*', 'pid_t*', 'unsigned*', '*']:
			arglist.append(arg + ' arg%i' % i)
		elif (components[0] == 'struct') and (len(components) <= 2):
			arglist.append(arg + ' arg%i' % i)
		elif components[-1].startswith('__'):
			arglist.append(arg + ' arg%i' % i)
		elif components[-1].endswith('_t'):
			arglist.append(arg + ' arg%i' % i)
		else:
			arglist.append(arg)

	for i, arg in enumerate(arglist):
		argstring += arg
		if i < len(arglist) - 1:
			argstring += ','
	return argstring

def get_sysid(funct, con_unistd):
	for i, line in enumerate(con_unistd):
		if funct in line:
			if '\t' in con_unistd[i - 1]:
				output = con_unistd[i - 1]
				output = output[output.find('\t'):].replace('\t', '')
				return output
			else:
				output = con_unistd[i - 1]
				output = output[output.find(' ', 10):].replace(' ', '')
				return output
	return 'ERROR'

def get_hookfunctions(functpointers, con_unistd):
	output = []
	for funct in functpointers:
		hook = '' #string to hold this hook function
		fullargs = get_arguments(funct[funct.find(')(') + 1:]).strip() #all arguments including types
		plainargs = get_arguments_names_only(funct[funct.find(')(') + 1:]).strip() #all arguments excluding types

		syscallname = funct[funct.find('ref_') + 4:funct.find(')')].strip()
		rettype = funct[:funct.find(' ')].strip()

		hookname = ('hook_' + syscallname).strip()
		refname = funct[funct.find('ref_'):funct.find(')')].strip()
		
		sysid = (get_sysid(syscallname, con_unistd)).strip()
		
		"""
		Special case: sys_exit_group doesn't return, so we call it AFTER sending the syscall metadata
		"""
		if 'sys_exit_group' in hookname:
			hook += '\n'
			hook += '%s %s(%s)\n' % (rettype, hookname, fullargs)
			hook += '{\n'
			hook += '\tif (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)\n'
			hook += '\t{\n'
			hook += '\t\tSYSCALL data;\n'
			hook += '\t\tdata.sys_id = %s;\n' % sysid
			hook += '\t\tdata.inode = get_inode();\n'
			hook += '\t\tdata.pid = current->pid;\n'
			hook += '\t\tdata.mem_loc = NULL;\n'
			hook += '\t\tmaldetect_nl_send_syscall(&data);\n'
			hook += '\t}\n'
			hook += '\treturn %s(%s);\n' % (rettype, refname, plainargs)
			hook += '}\n'
		else:
			hook += '\n'
			hook += '%s %s(%s)\n' % (rettype, hookname, fullargs)
			hook += '{\n'
			hook += '\t%s retval = %s(%s);\n' % (rettype, refname, plainargs)
			hook += '\tif (maldetect_userspace_pid > 0 && current->pid != maldetect_userspace_pid)\n'
			hook += '\t{\n'
			hook += '\t\tSYSCALL data;\n'
			hook += '\t\tdata.sys_id = %s;\n' % sysid
			hook += '\t\tdata.inode = get_inode();\n'
			hook += '\t\tdata.pid = current->pid;\n'
			hook += '\t\tdata.mem_loc = NULL;\n'
			hook += '\t\tmaldetect_nl_send_syscall(&data);\n'
			hook += '\t}\n'
			hook += '\treturn retval;\n'
			hook += '}\n'
		output.append(hook)
	return output

def get_defname(syscall, con_unistd):
	for line in con_unistd:
		if syscall in line:
			return line[line.find('(') + 1:line.find(',')]
	return 'ERROR'

def get_regunregfunctions(functpointers, con_unistd):
	output = []
	output.append('\n')
	output.append('void reg_hooks(unsigned long **syscall_table)\n')
	output.append('{\n')
	for funct in functpointers:
		refname = funct[funct.find('ref_'):funct.find(')')]
		defname = get_defname(refname[4:], con_unistd)
		hookname = refname.replace('ref_', 'hook_')

		output.append('\t%s = (void *)syscall_table[%s];\n' % (refname, defname))
		output.append('\tsyscall_table[%s] = (unsigned long *)%s;\n' % (defname, hookname))
	output.append('}\n')
	output.append('\n')
	output.append('void unreg_hooks(unsigned long **syscall_table)\n')
	output.append('{\n')
	for funct in functpointers:
		refname = funct[funct.find('ref_'):funct.find(')')]
		defname = get_defname(refname[4:], con_unistd)
		output.append('\tsyscall_table[%s] = (unsigned long *)%s;\n' % (defname, refname))
	output.append('}\n')
	return output

def gen_hooks(con_unistd, con_sys, f):
	includes = get_includes()
	for line in includes:
		f.write(line)

	functpointers = get_functpointers(con_unistd, con_sys[0], con_sys[1], con_sys[2])
	for line in functpointers:
		f.write(line + '\n')

	hooks = get_hookfunctions(functpointers, con_unistd)
	for line in hooks:
		f.write(line)

	regunreg = get_regunregfunctions(functpointers, con_unistd)
	for line in regunreg:
		f.write(line)

in_unistd = ''  # path to the unistd_xx.h header
in_sysarch = '' # path to the syscalls.h from arch/x/include/asm/syscalls.h
in_sysarchgen = '' # path to the syscalls.h from include/asm-generic/syscalls.h
in_sysgen = '' # path to the syscalls.h from include/linux/syscalls.h
con_unistd = '' # content for unistd
con_sysarch = ''
con_sysarchgen = ''
con_sysgen = ''
outfile = '' # path to the outfile, hooks.c for the loadable_kernel_module

try:
	opts, args = getopt.getopt(sys.argv[1:], '', ['unistd=', 'sysarch=', 'sysarchgen=', 'sysgen=', 'outfile='])
	for o, a in opts:
		if o in ('--unistd'):
			in_unistd = a
		elif o in ('--sysarch'):
			in_sysarch = a
		elif o in ('--sysarchgen'):
			in_sysarchgen = a
		elif o in ('--sysgen'):
			in_sysgen = a
		elif o in ('--outfile'):
			outfile = a
except getopt.GetoptError:
	usage()
	sys.exit(1)

if in_unistd is '' or in_sysarch is '' or in_sysarchgen is '' or in_sysgen is '' or outfile is '':
	usage()
	sys.exit(1)

with open(in_unistd, 'r') as f:
	con_unistd = f.readlines()
with open(in_sysarch, 'r') as f:
	con_sysarch = f.readlines()
with open(in_sysarchgen, 'r') as f:
	con_sysarchgen = f.readlines()
with open(in_sysgen, 'r') as f:
	con_sysgen = f.readlines()

f = open(outfile, 'a')
gen_hooks(con_unistd, (con_sysarch, con_sysarchgen, con_sysgen), f)
f.flush()
f.close()
