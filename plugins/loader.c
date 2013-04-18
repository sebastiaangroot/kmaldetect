#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <glob.h>
#include <string.h>
#include <pthread.h>
#include "libiface.h"

#define LIB_REGISTER_FNCT "lib_register_fnct"
#define LIB_ENTRY "lib_entry"
#define PLUGIN_FILTER "plugin/*.so"

void load_plugin(char *plugin_name)
{
	void (*entry_funct)(void);
	void (*register_funct)(void *, void *);
	void *lib_handle;
	char *error;
	pthread_t thread;

	lib_handle = dlopen(plugin_name, RTLD_LAZY);
	if (!lib_handle)
	{
		fprintf(stderr, "%s\n", dlerror());
		exit(1);
	}

	register_funct = dlsym(lib_handle, LIB_REGISTER_FNCT);
	if ((error = dlerror()) != NULL)
	{
		fprintf(stderr, "%s\n", error);
		exit(1);
	}

	entry_funct = dlsym(lib_handle, LIB_ENTRY);
	if ((error = dlerror()) != NULL)
	{
		fprintf(stderr, "%s\n", error);
		exit(1);
	}

	register_funct(&libiface_read, &libiface_write);
	//pthread_create(&thread, NULL, (void *(*)(void *)) entry_funct, NULL);
	entry_funct();
}

void load_plugins(void)
{
	int i;
	glob_t data;

	switch(glob(PLUGIN_FILTER, 0, NULL, &data))
	{
		case 0:
			break;
		case GLOB_NOSPACE:
			fprintf(stderr, "glob: Out of memory\n");
			exit(1);
		case GLOB_ABORTED:
			fprintf(stderr, "glob: Reading error\n");
			exit(1);
		case GLOB_NOMATCH:
			printf("load_plugins: No plugins found\n");
			return;
		default:
			fprintf(stderr, "glob: Unexpected error\n");
			exit(1);
	}

	for (i = 0; i < data.gl_pathc; i++)
	{
		printf("Found plugin: %s\n", data.gl_pathv[i]);
		load_plugin(data.gl_pathv[i]);
	}
	globfree(&data);
}
