#include <stdio.h>    
#include <stdlib.h>    
#include <asm/user.h>    
#include <asm/ptrace.h>    
#include <sys/ptrace.h>    
#include <sys/wait.h>    
#include <sys/mman.h>    
#include <dlfcn.h>    
#include <dirent.h>    
#include <unistd.h>    
#include <string.h>    
#include <elf.h>    

#define CPSR_T_MASK     ( 1u << 5 )    
#if defined(__i386__)    
#define pt_regs         user_regs_struct    
#endif 

const char *LIBC_PATH = "/system/lib/libc.so";
const char *LINKER_PATH = "/system/bin/linker";
const char* DEX_OPT_DIR = "/data/local/tmp/cache";

int ptrace_readdata(pid_t pid, uint8_t *src, uint8_t *buf, size_t size) {
	uint32_t i, j, remain;
	uint8_t *laddr;

	union u {
		long val;
		char chars[sizeof(long)];
	} d;

	j = size / 4;
	remain = size % 4;

	laddr = buf;

	for (i = 0; i < j; i++) {
		d.val = ptrace(PTRACE_PEEKTEXT, pid, src, 0);
		memcpy(laddr, d.chars, 4);
		src += 4;
		laddr += 4;
	}

	if (remain > 0) {
		d.val = ptrace(PTRACE_PEEKTEXT, pid, src, 0);
		memcpy(laddr, d.chars, remain);
	}

	return 0;
}

int ptrace_writedata(pid_t pid, uint8_t *dest, uint8_t *data, size_t size) {
	uint32_t i, j, remain;
	uint8_t *laddr;

	union u {
		long val;
		char chars[sizeof(long)];
	} d;

	j = size / 4;
	remain = size % 4;

	laddr = data;

	for (i = 0; i < j; i++) {
		memcpy(d.chars, laddr, 4);
		ptrace(PTRACE_POKETEXT, pid, dest, (void *) d.val);

		dest += 4;
		laddr += 4;
	}

	if (remain > 0) {
		d.val = ptrace(PTRACE_PEEKTEXT, pid, dest, 0);
		for (i = 0; i < remain; i++) {
			d.chars[i] = *laddr++;
		}

		ptrace(PTRACE_POKETEXT, pid, dest, (void *) d.val);
	}

	return 0;
}

#if defined(__arm__)    
int ptrace_call(pid_t pid, uint32_t addr, long *params, uint32_t num_params, struct pt_regs* regs)
{
	uint32_t i;
	for (i = 0; i < num_params && i < 4; i ++) {
		regs->uregs[i] = params[i];
	}

	// Pushes remained params onto stack
	if (i < num_params) {
		regs->ARM_sp -= (num_params - i) * sizeof(long);
		ptrace_writedata(pid, (void *)regs->ARM_sp, (uint8_t *)&params[i], (num_params - i) * sizeof(long));
	}

	regs->ARM_pc = addr;
	if (regs->ARM_pc & 1) {
		// For thumb 
		regs->ARM_pc &= (~1u);
		regs->ARM_cpsr |= CPSR_T_MASK;
	} else {
		// For arm
		regs->ARM_cpsr &= ~CPSR_T_MASK;
	}

	regs->ARM_lr = 0;

	if (ptrace_setregs(pid, regs) == -1 || ptrace_continue(pid) == -1) {
		printf("error\n");
		return -1;
	}

	int stat = 0;
	waitpid(pid, &stat, WUNTRACED);
	while (stat != 0xb7f) {
		if (ptrace_continue(pid) == -1) {
			printf("error\n");
			return -1;
		}
		waitpid(pid, &stat, WUNTRACED);
	}

	return 0;
}

#elif defined(__i386__)    
long ptrace_call(pid_t pid, uint32_t addr, long *params, uint32_t num_params, struct user_regs_struct * regs)
{
	regs->esp -= (num_params) * sizeof(long);
	ptrace_writedata(pid, (void *)regs->esp, (uint8_t *)params, (num_params) * sizeof(long));

	long tmp_addr = 0x00;
	regs->esp -= sizeof(long);
	ptrace_writedata(pid, regs->esp, (char *)&tmp_addr, sizeof(tmp_addr));

	regs->eip = addr;

	if (ptrace_setregs(pid, regs) == -1 || ptrace_continue( pid) == -1) {
		printf("error\n");
		return -1;
	}

	int stat = 0;
	waitpid(pid, &stat, WUNTRACED);
	while (stat != 0xb7f) {
		if (ptrace_continue(pid) == -1) {
			printf("error\n");
			return -1;
		}
		waitpid(pid, &stat, WUNTRACED);
	}

	return 0;
}
#else     
#error "Not supported"    
#endif

int ptrace_getregs(pid_t pid, struct pt_regs * regs) {
	if (ptrace(PTRACE_GETREGS, pid, NULL, regs) < 0) {
		perror("ptrace_getregs: Can not get register values");
		return -1;
	}

	return 0;
}

int ptrace_setregs(pid_t pid, struct pt_regs * regs) {
	if (ptrace(PTRACE_SETREGS, pid, NULL, regs) < 0) {
		perror("ptrace_setregs: Can not set register values");
		return -1;
	}

	return 0;
}

int ptrace_continue(pid_t pid) {
	if (ptrace(PTRACE_CONT, pid, NULL, 0) < 0) {
		perror("ptrace_cont");
		return -1;
	}

	return 0;
}

int ptrace_attach(pid_t pid) {
	if (ptrace(PTRACE_ATTACH, pid, NULL, 0) < 0) {
		perror("ptrace_attach");
		return -1;
	}

	int status = 0;
	waitpid(pid, &status, WUNTRACED);

	return 0;
}

int ptrace_detach(pid_t pid) {
	if (ptrace(PTRACE_DETACH, pid, NULL, 0) < 0) {
		perror("ptrace_detach");
		return -1;
	}

	return 0;
}

void* get_module_base(pid_t pid, const char* module_name) {
	FILE *fp;
	long addr = 0;
	char *pch;
	char filename[32];
	char line[1024];

	if (pid < 0) {
		// Self process
		snprintf(filename, sizeof(filename), "/proc/self/maps");
	} else {
		snprintf(filename, sizeof(filename), "/proc/%d/maps", pid);
	}

	fp = fopen(filename, "r");

	if (fp != NULL ) {
		while (fgets(line, sizeof(line), fp)) {
			if (strstr(line, module_name)) {
				pch = strtok(line, "-");
				addr = strtoul(pch, NULL, 16);

				if (addr == 0x8000)
					addr = 0;

				break;
			}
		}

		fclose(fp);
	}

	return (void *) addr;
}

void* get_remote_addr(pid_t target_pid, const char* module_name,
		void* local_addr) {
	void* local_handle, *remote_handle;

	local_handle = get_module_base(-1, module_name);
	remote_handle = get_module_base(target_pid, module_name);

	fprintf(stdout, "[+] Get remote address: local[%p], remote[%p]\n", local_handle, remote_handle);
	void * ret_addr = (void *) ((uint32_t) local_addr + (uint32_t) remote_handle - (uint32_t) local_handle);

#if defined(__i386__)    
	if (!strcmp(module_name, LIBC_PATH)) {
		ret_addr += 2;
	}
#endif    
	return ret_addr;
}

int find_pid_of(const char *process_name) {
	int id;
	pid_t pid = -1;
	DIR* dir;
	FILE *fp;
	char filename[32];
	char cmdline[256];

	struct dirent * entry;

	if (process_name == NULL )
		return -1;

	dir = opendir("/proc");
	if (dir == NULL )
		return -1;

	while ((entry = readdir(dir)) != NULL ) {
		id = atoi(entry->d_name);
		if (id != 0) {
			sprintf(filename, "/proc/%d/cmdline", id);
			fp = fopen(filename, "r");
			if (fp) {
				fgets(cmdline, sizeof(cmdline), fp);
				fclose(fp);

				if (strcmp(process_name, cmdline) == 0) {
					// Target process found
					pid = id;
					break;
				}
			}
		}
	}

	closedir(dir);
	return pid;
}

long ptrace_retval(struct pt_regs * regs) {
#if defined(__arm__)    
	return regs->ARM_r0;
#elif defined(__i386__)    
	return regs->eax;
#else    
#error "Not supported"    
#endif    
}

long ptrace_ip(struct pt_regs * regs) {
#if defined(__arm__)    
	return regs->ARM_pc;
#elif defined(__i386__)    
	return regs->eip;
#else    
#error "Not supported"    
#endif    
}

int ptrace_call_wrapper(pid_t target_pid, const char * func_name,
		void * func_addr, long * parameters, int param_num,
		struct pt_regs * regs) {
	fprintf(stdout, "[+] Calling %s in target process.\n", func_name);
	if (ptrace_call(target_pid, (uint32_t) func_addr, parameters, param_num, regs) == -1)
		return -1;

	if (ptrace_getregs(target_pid, regs) == -1)
		return -1;
	fprintf(stdout,"[+] Target process returned from %s, return value=0x%08x, pc=0x%08x \n",
            func_name, (uint32_t) ptrace_retval(regs), (uint32_t) ptrace_ip(regs));
	return 0;
}

int inject_remote_process(pid_t target_pid, const char *payload_path, const char *payload_method_name, 
	const char *cache_path, const char *warhead_path, const char * warhead_class_name, const char * warhead_method_name) {
	int ret = 0;
	void *mmap_addr, *dlopen_addr, *dlsym_addr, *dlclose_addr, *dlerror_addr;
	void *local_handle, *remote_handle, *dlhandle;
	uint8_t *map_base = 0;
	uint8_t *dlopen_param1_ptr, *dlsym_param2_ptr, *saved_r0_pc_ptr,
			*inject_param_ptr, *remote_code_ptr, *local_code_ptr;

	struct pt_regs regs, *original_regs = 0;
	extern uint32_t _dlopen_addr_s, _dlopen_param1_s, _dlopen_param2_s,
			_dlsym_addr_s, _dlsym_param2_s, _dlclose_addr_s, _inject_start_s,
			_inject_end_s, _inject_function_param_s, _saved_cpsr_s,
			_saved_r0_pc_s;

	uint32_t code_length;
	long parameters[10];

	fprintf(stdout, "[+] Injecting process: %d\n", target_pid);

	do {
		if (ptrace_attach(target_pid) == -1) {
			fprintf(stderr, "[+] ptrace_attach error!\n");
			ret = -10;
			break;
		}

		if (ptrace_getregs(target_pid, &regs) == -1) {
			fprintf(stderr, "[+] ptrace_getregs error!\n");
			ret = -11;
			break;
		}

		// Saves original registers
		original_regs = calloc(sizeof(regs), 1);
		memcpy(original_regs, &regs, sizeof(regs));

		mmap_addr = get_remote_addr(target_pid, LIBC_PATH, (void *) mmap);
		fprintf(stdout, "[+] Remote mmap address: %p\n", mmap_addr);

		// Calls mmap
		parameters[0] = 0;  // addr
		parameters[1] = 0x4000; // size
		parameters[2] = PROT_READ | PROT_WRITE | PROT_EXEC; // prot
		parameters[3] = MAP_ANONYMOUS | MAP_PRIVATE; // flags
		parameters[4] = 0; // fd
		parameters[5] = 0; // offset

		if (ptrace_call_wrapper(target_pid, "mmap", mmap_addr, parameters, 6, &regs)
				== -1) {
			fprintf(stderr, "[+] ptrace_call_wrapper mmap error!\n");
			ret = -12;
			break;
		}

		map_base = (uint8_t *) ptrace_retval(&regs);

		dlopen_addr = get_remote_addr(target_pid, LINKER_PATH, (void *) dlopen);
		dlsym_addr = get_remote_addr(target_pid, LINKER_PATH, (void *) dlsym);
		dlclose_addr = get_remote_addr(target_pid, LINKER_PATH, (void *) dlclose);
		dlerror_addr = get_remote_addr(target_pid, LINKER_PATH, (void *) dlerror);

		fprintf(stdout,"[+] Get imports: dlopen: %p, dlsym: %p, dlclose: %p, dlerror: %p\n",
				dlopen_addr, dlsym_addr, dlclose_addr, dlerror_addr);
		fprintf(stdout, "[+] library path = %s\n", payload_path);
		ptrace_writedata(target_pid, map_base, (uint8_t *) payload_path, strlen(payload_path) + 1);

		parameters[0] = (int) map_base;
		parameters[1] = RTLD_NOW | RTLD_GLOBAL;

		if (ptrace_call_wrapper(target_pid, "dlopen", dlopen_addr, parameters, 2, &regs) == -1) {
			fprintf(stderr, "[+] ptrace_call_wrapper dlopen error!\n");
			ret = -13;
			break;
		}

		void * sohandle = (void *) ptrace_retval(&regs);

#define FUNCTION_NAME_ADDR_OFFSET       0x100
		ptrace_writedata(target_pid, map_base + FUNCTION_NAME_ADDR_OFFSET,
				(uint8_t *) payload_method_name, strlen(payload_method_name) + 1);
		parameters[0] = (int) sohandle;
		parameters[1] = (int) (map_base + FUNCTION_NAME_ADDR_OFFSET);

		if (ptrace_call_wrapper(target_pid, "dlsym", dlsym_addr, parameters, 2, &regs) == -1) {
			fprintf(stderr, "[+] ptrace_call_wrapper dlsym error!\n");
			ret = -14;
			break;
		}

		void * hook_entry_addr = (void*) ptrace_retval(&regs);
		fprintf(stdout, "[+] hook_entry_addr = %p\n", hook_entry_addr);

#define FUNCTION_PARAM0_ADDR_OFFSET      0x200
#define FUNCTION_PARAM1_ADDR_OFFSET      0x300

#define FUNCTION_PARAM2_ADDR_OFFSET      0x600
#define FUNCTION_PARAM3_ADDR_OFFSET      0x700
		ptrace_writedata(target_pid, map_base + FUNCTION_PARAM0_ADDR_OFFSET,
				(uint8_t *) cache_path, strlen(cache_path) + 1);
		ptrace_writedata(target_pid, map_base + FUNCTION_PARAM1_ADDR_OFFSET,
						(uint8_t *) warhead_path, strlen(warhead_path) + 1);
		ptrace_writedata(target_pid, map_base + FUNCTION_PARAM2_ADDR_OFFSET,
				(uint8_t *) warhead_class_name, strlen(warhead_class_name) + 1);
		ptrace_writedata(target_pid, map_base + FUNCTION_PARAM3_ADDR_OFFSET,
				(uint8_t *) warhead_method_name, strlen(warhead_method_name) + 1);
		parameters[0] = (int) (map_base + FUNCTION_PARAM0_ADDR_OFFSET);
		parameters[1] = (int) (map_base + FUNCTION_PARAM1_ADDR_OFFSET);
		parameters[2] = (int) (map_base + FUNCTION_PARAM2_ADDR_OFFSET);
		parameters[3] = (int) (map_base + FUNCTION_PARAM3_ADDR_OFFSET);

		if (ptrace_call_wrapper(target_pid, "hook_entry", hook_entry_addr, parameters, 3+1, &regs) == -1) {
			fprintf(stderr, "[+] ptrace_call_wrapper hook_entry error!\n");
			ret = -15;
			break;
		}

		parameters[0] = (int) sohandle;
		
//		if (ptrace_call_wrapper(target_pid, "dlclose", dlclose, parameters, 1, &regs) == -1) {
//			fprintf(stderr, "[+] ptrace_call_wrapper dlclose error!\n");
//			ret = -16;
//			break;
//		}
	} while(0);

	// Restores
	if (original_regs) {
		ptrace_setregs(target_pid, original_regs);
		free(original_regs);
	}
	ptrace_detach(target_pid);

	if (ret < 0) {
		fprintf(stderr, "[+] inject error %d, %s!\n", errno, strerror(errno));
	}
	return ret;
}

pid_t find_pid( const char *process_name )
{
    int id;
    pid_t pid = -1;
    DIR *dir;
    FILE *fp;
    char filename[32];
    char cmdline[256];

    struct dirent * entry;

    if ( process_name == NULL )
        return -1;

    dir = opendir( "/proc" );
    if ( dir == NULL )
        return -1;

    while( (entry = readdir( dir )) != NULL )
    {
        id = atoi( entry->d_name );
        if ( id != 0 )
        {
            sprintf( filename, "/proc/%d/cmdline", id );
            fp = fopen( filename, "r" );
            if ( fp )
            {
                fgets( cmdline, sizeof(cmdline), fp );
                fclose( fp );

                if ( strcmp( process_name, cmdline ) == 0 ) // process found
                {
                    pid = id;
                    break;
                }
            }
        }
    }

    closedir( dir );

    return pid;
}

int main(int argc, char** argv) {
	pid_t target_pid;
	char *process_name, *payload_path, *payload_method_name,
	*warhead_path, *warhead_class_name, *warhead_method_name;

	if (argc != 7) {
		fprintf(stderr, "[+] Invalid number of arguments.\n");
		return -1;
	}

	process_name = argv[1];
	payload_path = argv[2];
	payload_method_name = argv[3];
	warhead_path = argv[4];
	warhead_class_name = argv[5];
	warhead_method_name = argv[6];
	
	target_pid = find_pid(process_name);
	
	if (-1 == target_pid) {
		fprintf(stderr, "[+] Error getting pid of %s\n", process_name);
		return -2;
	}

	return inject_remote_process(target_pid, payload_path, payload_method_name, 
		DEX_OPT_DIR, warhead_path, warhead_class_name, warhead_method_name);
}
