"""
A simple python script to generate a sh table that takes the name of a syscall as input and translates it to the number corrosponding with that syscall.
This function is used in the sig_gen.sh script, used to generate an application signature for detection in kmaldetect.
Keep in mind that the '\n' characters used here will be translated to your OS's newline convention.
"""

import sys
import getopt

def gen_function(content, f):
	f.write('function get_syscall_index\n')
	f.write('{\n')
	f.write('\tcase $1 in\n')
	for line in content:
		if line.startswith('#define __NR_') and line.find('stub_') == -1:
			if line[9:].find('\t') != -1:
				num = line[line.find('\t', line.find('__NR_')):].lstrip('\t').strip() #num = the characters after the tab / whitespace characters, after the _NR__
				name = line[line.find('__NR_') + 5:].split('\t')[0] #name = the characters after the _NR__ but before the tab / whitespace characters
			elif line[9:].find(' ') != -1:
				num = line[line.find(' ', line.find('__NR_')):].lstrip(' ').strip()
				name = line[line.find('__NR_') + 5:].split(' ')[0]
			else: #There has to be a space or tab after the #define _NR__xxx. This was not the case, so call continue on the for loop
				continue
			f.write('\t\t\'' + name + '\')\n')
			f.write('\t\t\treturn ' + num + '\n')
			f.write('\t\t\t;;\n')
	f.write('\tesac\n')
	f.write('}\n')

infile = ''  # path to the unistd_xx.h header
outfile = '' # path to the outfile, which will be filled with a .sh function for the use in sig_gen.sh
content = '' # content of infile

opts, args = getopt.getopt(sys.argv[1:], 'i:o:', ['infile=', 'outfile='])
for o, a in opts:
	if o in ('--infile', '-i'):
		infile = a
	elif o in ('--outfile', '-o'):
		outfile = a

with open(infile, 'r') as f:
	content = f.readlines()

f = open(outfile, 'a')
gen_function(content, f)
f.flush()
f.close()