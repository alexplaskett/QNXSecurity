
#include <sys/memmsg.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/neutrino.h>

// Message structs
#include <sys/procmsg.h>

#include <sys/sysmsg.h>

#include <sys/rsrcdbmsg.h>
//#include <sys/procmgr.h>

#include <sys/iomsg.h>
#include <fcntl.h>
#include <share.h>

#include <dirent.h>

//#define QNX65

// Taken from netusse
int evilint(void)
{
    int         state;
    unsigned    common_sizeofs[] = { 16, 32, 64, 128, 256 };
#define _SIZEOFRAND ((rand() % 4) ? 1 : common_sizeofs[rand()%(sizeof(common_sizeofs)/sizeof(common_sizeofs[0]))]);
    state = rand() % 20;
    switch ( state )
    {
        case 0:
            return rand();
            break;
        case 1:
            return( 0xffffff00 | (rand() % 256));
        case 2: return 0x8000 / _SIZEOFRAND;
        case 3: return 0xffff / _SIZEOFRAND;
        case 4: return 0x80000000 / _SIZEOFRAND;
        case 5: return -1;
        case 6: return 0xff;
        case 7: return 0x7fffffff / _SIZEOFRAND;
        case 8: return 0;
        case 9: return 4;
        case 10: return 8;
        case 11: return 12;
        case 12: return 0xffffffff / _SIZEOFRAND
        case 13:
        case 14:
                 return rand() & 256;
        default:
                return rand();

    }
}

///////////////////////////////// MEMMGR //////////////////////////////////////////////////

// _MEM_DEBUG_INFO
void fuzz_memmgr_debug_info() {
	iov_t						iov[2];
	mem_debug_info_t			msg;


	msg.i.type = _MEM_DEBUG_INFO;
	msg.i.zero = msg.i.reserved = 0;
	msg.i.offset = 20;
	msg.i.ino = 0;
	msg.i.vaddr = 0x20;
	msg.i.size = 20;
	msg.i.flags = 0;
	msg.i.dev = 0;
	msg.i.old_vaddr = 20;
	msg.i.path[0] = '\0';

	// TODO: Fix this
	//SETIOV(iov+0,&msg.i,offsetof(mem_debug_info_t,i.path));
	//SETIOV(iov + 0, &msg.i, offsetof(mem_debug_info_t, i.path));
	SETIOV(iov + 1, "aaaa", 20 + 1);

	(void) MsgSendv(MEMMGR_COID, iov, 2, 0, 0);
}

void fuzz_memmgr_map()
{
	mem_map_t						msg;

	void *addr = rand();
	int len = rand();
	int prot = rand();
	int flags = rand();
	int fd = NOFD;
	int off = rand();
	int align = rand();
	int preload = rand();

	msg.i.type = _MEM_MAP;
	msg.i.zero = 0;
	msg.i.addr = addr;
	msg.i.len = len;
	msg.i.prot = prot;
	msg.i.flags = flags;
	msg.i.fd = fd;
	msg.i.offset = off;
	msg.i.align = align;
	msg.i.preload = preload;
	msg.i.reserved1 = 0;

	if(MsgSendnc(MEMMGR_COID, &msg.i, sizeof msg.i, &msg.o, sizeof msg.o) == -1) {
		perror("_MEM_MAP");
	}
	else
	{
		printf("addr %d\n", msg.o.real_addr);
	}
}

void fuzz_memmgr_ctrl()
{
	mem_ctrl_t						msg;
	void *addr = rand();
	int len = rand();

	msg.i.type = _MEM_CTRL;
	msg.i.subtype = rand() % 8;
	msg.i.addr = addr;
	msg.i.len = len;
	msg.i.flags = rand();

	if(MsgSendnc(MEMMGR_COID, &msg.i, sizeof msg.i, 0, 0) == -1) {
		perror("_MEM_CTRL_LOCK");
	}

}

void fuzz_memmgr_info()
{
	mem_info_t						msg;
	iov_t							iov[3];
	struct posix_typed_mem_info info;

	int fd = 0;
	int flags = 0;

	msg.i.type = _MEM_INFO;
	msg.i.zero = 0;
	msg.i.fd = fd;
	msg.i.flags = flags;
	SETIOV(iov + 0, &msg.i, sizeof msg.i);
	//SETIOV(iov + 1, &msg.o, offsetof(struct _mem_info_reply, info));
	SETIOV(iov + 2, &info, sizeof info);

	MsgSendvnc(MEMMGR_COID, iov + 0, 1, iov + 1, 2);
}

void fuzz_memmgr_offset()
{
	mem_offset_t					msg;
	void * addr = 0;
	int subtype = rand() % 3; // 0 - 4 (permission denied though).
	int len = rand();

	msg.i.type = _MEM_OFFSET;
	msg.i.subtype = subtype;
	msg.i.addr = addr;
	msg.i.reserved = -1;
	msg.i.len = len;


	if (MsgSendnc(MEMMGR_COID, &msg.i, sizeof msg.i, &msg.o, sizeof msg.o) == -1) {
		perror("_MEM_OFFSET");
	}
}

void fuzz_memmgr_debug_cmd()
{
	// Not implemented anywhere.
}

// _MEM_SWAP
void fuzz_memmgr_swap()
{
	mem_swap_t msg;

	msg.swap_on.type = _MEM_SWAP;
	msg.swap_on.subtype = rand() % 4;

	if (MsgSendnc(MEMMGR_COID, &msg.swap_on, sizeof msg.swap_on, 0, 0) == -1) {
			perror("_MEM_SWAP");
	}

}


// _MEM_PMEM_ADD

void fuzz_memmgr_pmem_add()
{
	// Should check if proc is root first before allowing this.
	mem_pmem_add_t msg;

	msg.i.type = _MEM_PMEM_ADD;
	msg.i.addr = rand();
	msg.i.len = rand();
	msg.i.zero1 = 0;
	msg.i.zero2 = 0;

	if (MsgSendnc(MEMMGR_COID, &msg.i, sizeof msg.i, 0, 0) == -1) {
			perror("_MEM_PMEM_ADD");
	}
}

void fuzz_memmgr_peer()
{

	mem_peer_t msg;
	msg.i.type = _MEM_PEER;
	msg.i.pid = getpid();
	msg.i.peer_msg_len = rand();
	msg.i.reserved1 = 0;

	if (MsgSendnc(MEMMGR_COID, &msg.i, sizeof msg.i, 0, 0) == -1) {
			perror("_MEM_PEER");
	}

}


/**
 * Procmsg fuzzer
 */


/////////////////////////////////////////////////////////////////////////////////////////////////////


// _PROC_SPAWN/_PROC_SPAWN_START
void fuzz_proc_spawn()
{
	proc_spawn_t					msg = {0};
	iov_t							iov[6];
	char * const *argv;
	char * const *envp;
	char							*dst;
	char							*const *arg;
	pid_t							pid;

	char *path = "ps";
	char *search = 0; //getenv("PATH");
	char *data = "/base/bin/ls";

	msg.i.type = _PROC_SPAWN;
	msg.i.subtype = _PROC_SPAWN_START;
	msg.i.parms.flags = 0;
	msg.i.nfds = 0;

	int fd_map[10];
	int fd_count = 10;

	//argv[0] = "test";
	//envp[0] = "test";


	msg.i.nbytes = msg.i.nargv = msg.i.narge = 0;

	msg.i.nbytes = rand();
	msg.i.narge = rand();
	msg.i.narge = rand();

	// Alloc the data

	SETIOV(iov + 0, &msg.i, sizeof msg.i);
	SETIOV(iov + 1, fd_map, fd_count * sizeof fd_map[0]);
	SETIOV(iov + 2, search, msg.i.searchlen = (search ? strlen(search) + 1 : 0));
	SETIOV(iov + 3, path, msg.i.pathlen = strlen(path) + 1);
	SETIOV(iov + 4, data, msg.i.nbytes);

	pid = MsgSendvnc(PROCMGR_COID, iov + 0, 6, 0, 0);
	if (pid == -1)
		perror("_PROC_SPAWN/_PROC_SPAWN_START");

}


// _PROC_SPAWN/_PROC_SPAWN_FD
// This currently blocks on the fd passed.
void fuzz_proc_spawnfd()
{
	proc_spawn_fd_t msg;

	pid_t							pid;
	iov_t							iov[2];

	msg.i.type = _PROC_SPAWN;
	msg.i.subtype = _PROC_SPAWN_FD;
	msg.i.flags = _PROC_SPAWN_FD_LIST;
	msg.i.nfds = 0;
	msg.i.base = 0;
	msg.i.ppid = 0;

	SETIOV(iov + 0, &msg.i, sizeof msg.i);

	pid = MsgSendvnc(PROCMGR_COID, iov + 0, 1, 0, 0);


	if (pid == -1)
		perror("_PROC_SPAWN/_PROC_SPAWN_FD");
}

// _PROC_SPAWN/_PROC_SPAWN_ARGS
// This function seems not to be implemented.
void fuzz_spawn_args()
{
	proc_spawn_args_t msg;

	msg.i.type = _PROC_SPAWN;
	msg.i.subtype = _PROC_SPAWN_ARGS;
	msg.i.nbytes = rand();
	msg.i.offset = rand();
	msg.i.zero = rand();
	char *strings = "/base/bin/ls";
	int interplen = rand();

	if(MsgSend(PROCMGR_COID, &msg.i, sizeof msg.i,strings + interplen, msg.i.nbytes) == -1) {
		perror("_PROC_SPAWN/_PROC_SPAWN_ARGS");
	}

}

// _PROC_SPAWN/_PROC_SPAWN_DONE
// This function seems not implemented.
void fuzz_proc_spawn_done()
{
	proc_spawn_done_t msg;

	msg.i.type = _PROC_SPAWN;
	msg.i.subtype = _PROC_SPAWN_DONE;
	msg.i.rcvid = rand();

	if(MsgSend(PROCMGR_COID, &msg.i, sizeof msg.i,0, 0) == -1) {
		perror("_PROC_SPAWN/_PROC_SPAWN_DONE");
	}
}

// _PROC_SPAWN/_PROC_SPAWN_DEBUG
// This function is not implemented.
void fuzz_proc_spawn_debug()
{
	proc_spawn_debug_t msg;

	msg.i.type = _PROC_SPAWN;
	msg.i.subtype = _PROC_SPAWN_DEBUG;

	/**
	 * 	_Uint32t						text_addr;
	_Uint32t						text_size;
	_Int32t							text_reloc;
	_Uint32t						data_addr;
	_Uint32t						data_size;
	_Int32t							data_reloc;
	char							name[1];
	 */
	if(MsgSend(PROCMGR_COID, &msg.i, sizeof msg.i,0, 0) == -1) {
		perror("_PROC_SPAWN/_PROC_SPAWN_DONE");
	}
}

// end of _PROC_SPAWN

// _PROC_POSIX_SPAWN
// Broken.
void fuzz_proc_posix_spawn()
{
	proc_posixspawn_t				msg = {0};
	const posix_spawnattr_t * _Restrict attrp;
	void				*_attrp;

	char * path = "/bin/ls";
	char *data = "hmm";

	unsigned						factp_open_iovs = 0;
	iov_t							iov[6];
	//if (attrp == NULL) attrp = &default_posix_spawnattr_t;



	msg.i.type = _PROC_POSIX_SPAWN;
	msg.i.subtype = _PROC_SPAWN_START;
	msg.i.pathlen = strlen(path) + 1;
	msg.i.attr_bytes = -1;
	msg.i.narge = rand();
	msg.i.nargv = rand();


	SETIOV(iov + 0, &msg.i, sizeof msg.i);
	SETIOV(iov + 1, path, msg.i.pathlen);

	//SETIOV(iov + 1, _attrp, msg.i.attr_bytes);
	//SETIOV(iov + 2, path, msg.i.pathlen);
	//SETIOV(iov + 3, path, msg.i.pathlen);
	//SETIOV(iov + 4, path, msg.i.pathlen);


	//SETIOV(iov + 3 + factp_open_iovs, path, msg.i.pathlen);
	//SETIOV(iov + 4 + factp_open_iovs, data, msg.i.argenv_bytes);

	if (MsgSendvnc(PROCMGR_COID, iov + 0, 2, 0, 0) == -1)
	{
		perror("_PROC_POSIX_SPAWN");
	}
}

////////////////////////////////////////////////////////////////////////////////////////

// _PROC_WAIT
// procmgr_wait
void fuzz_proc_wait()
{

	typedef enum {
		P_ALL,
		P_PID,
		P_PGID
	} idtype_t;

	proc_wait_t					msg;
	iov_t						iov[2];
	siginfo_t * infop;


	msg.i.type = _PROC_WAIT;
	msg.i.idtype = rand();
	msg.i.id = rand();
	msg.i.options = rand();

	SETIOV(iov + 0, &msg.i, sizeof msg.i);
	SETIOV(iov + 1, infop, sizeof *infop);

	if (MsgSendv(PROCMGR_COID, iov + 0, 1, iov + 1, infop ? 1 : 0) == -1)
	{
		perror("_PROC_WAIT");
	}
}

// _PROC_FORK
// procmgr_fork
void fuzz_proc_fork()
{
	proc_fork_t					msg;
	pid_t						pid;
	uintptr_t frame;

	msg.i.type = _PROC_FORK;
	msg.i.zero = 0;
	msg.i.flags = rand() % 20;			// _FORK_ASPACE
	msg.i.frame = rand();			// ??? 64bit ptr
	//msg.i.frame = 0;

	if (MsgSendnc(PROCMGR_COID, &msg.i, sizeof msg.i, 0, 0) == -1)
	{
		perror("_PROC_FORK");
	}
	else
	{
		printf("fork ok\n");
	}
}

// _PROC_GETSETID
// procmgr_getsetid
void fuzz_proc_getsetid()
{
	proc_getsetid_t				msg;
	int ret = -1;

	msg.i.type = _PROC_GETSETID;
	msg.i.subtype = _PROC_ID_SETGROUPS;
	msg.i.pid = rand();
	msg.i.ngroups = rand();


	ret = MsgSendnc(PROCMGR_COID, &msg.i, sizeof msg.i, &msg.o, sizeof msg.o);
	printf("_PROC_GETSETID = %d\n",ret);
	if (ret == -1)
		perror("Error");

}

// _PROC_SETPGID
// procmgr_setpgid
void fuzz_proc_setpgid()
{
	proc_setpgid_t					msg;
	pid_t pid;
	pid_t pgid;
	int ret = -1;


	msg.i.type = _PROC_SETPGID;
	msg.i.pid = getpid();
	msg.i.pgid = 0;

	ret = MsgSendnc(PROCMGR_COID, &msg.i, sizeof msg.i, 0, 0);

	ret = setpgid(getpid(),0);

	setpgid(getpid(),0);

	printf("_PROC_SETPGID = %d\n",ret);
	if (ret == -1)
		perror("Error");

	printf("Get PGID : %d\n", getpgid(getpid()));

}

// _PROC_UMASK
// procmgr_umask
void fuzz_proc_umask()
{
	proc_umask_t				msg;
	pid_t pid;
	mode_t cmask;
	int ret = -1;


	msg.i.type = _PROC_UMASK;
	msg.i.subtype = _PROC_UMASK_SET;
	msg.i.umask = cmask;
	msg.i.pid = pid;

	ret = MsgSendnc(PROCMGR_COID, &msg.i, sizeof msg.i, &msg.o, sizeof msg.o);

	printf("_PROC_UMASK = %d\n",ret);
	if (ret == -1)
		perror("Error");

}

// _PROC_GUARDIAN
// This function seems to block
void fuzz_proc_guardian()
{
	proc_guardian_t			msg;
	pid_t pid;
	int ret = -1;

	msg.i.type = _PROC_GUARDIAN;
	msg.i.subtype = 0;
	msg.i.pid = 0;

	ret = MsgSendnc(PROCMGR_COID, &msg.i, sizeof msg.i, &msg.o, sizeof msg.o);

	printf("_PROC_GUARDIAN = %d\n",ret);
	if (ret == -1)
		perror("Error");
}

// _PROC_SESSION
void fuzz_proc_session()
{
	proc_session_t			msg;
	pid_t sid;
	int id;
	unsigned event;
	int ret = -1;

	msg.i.type = _PROC_SESSION;
	msg.i.subtype = 0;
	msg.i.sid = 0;
	msg.i.id = 0;
	msg.i.event = 0;

	ret = MsgSendnc(PROCMGR_COID, &msg.i, sizeof msg.i, 0, 0);


	printf("_PROC_SESSION = %d\n",ret);
	if (ret == -1)
		perror("Error");
}

// _PROC_DAEMON
void fuzz_proc_daemon()
{
	proc_daemon_t			msg;
	int						nfds;
	int status = 0;
	unsigned flags = 0;
	int ret = -1;


	msg.i.type = _PROC_DAEMON;
	msg.i.subtype = 0;
	msg.i.status = status;
	msg.i.flags = flags;

	ret = MsgSendnc(PROCMGR_COID, &msg.i, sizeof msg.i, 0, 0);

	printf("_PROC_DAEMON = %d\n",ret);
	if (ret == -1)
		perror("Error");
}

// _PROC_EVENT
void fuzz_proc_event()
{
	unsigned flags;
	proc_event_t			msg;
	int ret = -1;


	msg.i.type = _PROC_EVENT;
	msg.i.subtype = _PROC_EVENT_TRIGGER;
	msg.i.flags = flags;

	ret = MsgSendnc(PROCMGR_COID, &msg.i, sizeof msg.i, 0, 0);

	printf("_PROC_EVENT = %d\n",ret);
	if (ret == -1)
		perror("Error");

}

// _PROC_RESOURCE/_PROC_RESOURCE_USAGE
void fuzz_proc_resource_usage()
{
	proc_resource_usage_t msg;
	int ret = -1;


	msg.i.type = _PROC_RESOURCE;
	msg.i.subtype = _PROC_RESOURCE_USAGE;
	msg.i.pid = 0;
	msg.i.who = 0;

	ret = MsgSendnc(PROCMGR_COID, &msg.i, sizeof msg.i, 0, 0);

	printf("_PROC_RESOURCE/_PROC_RESOURCE_USAGE = %d\n",ret);
	if (ret == -1)
		perror("Error");

}

//  _PROC_RESOURCE/_PROC_RESOURCE_GETLIMIT
// _PROC_RESOURCE/_PROC_RESOURCE_SETLIMIT
void fuzz_proc_resource_getlimit()
{
	proc_resource_getlimit_t msg;
	int ret = -1;

	msg.i.type = _PROC_RESOURCE;
	msg.i.subtype = _PROC_RESOURCE_GETLIMIT;
	msg.i.count = rand();
	msg.i.pid = rand();
	msg.i.reserved = rand();
	msg.i.resource[0] = rand();

	ret = MsgSendnc(PROCMGR_COID, &msg.i, sizeof msg.i, 0, 0);

	printf("_PROC_RESOURCE/_PROC_RESOURCE_GETLIMIT = %d\n",ret);
	if (ret == -1)
		perror("Error");

}

// _PROC_RESOURCE/_PROC_RESOURCE_LOOKUPABILITY,_PROC_RESOURCE_CREATEABILITY
// TODO: Figure out how namelen works.
void fuzz_proc_resource_lookupability()
{
	proc_resource_lookupability_t msg;
	int ret = -1;

	msg.i.type = _PROC_RESOURCE;
	msg.i.subtype = _PROC_RESOURCE_LOOKUPABILITY;
	msg.i.pid = rand();
	msg.i.namelen = rand(); 												// There's a limit on the size of the arg list.

	ret = MsgSendnc(PROCMGR_COID, &msg.i, sizeof msg.i, 0, 0);

	printf("_PROC_RESOURCE/_PROC_RESOURCE_LOOKUPABILITY ret = %d\n",ret);
	if (ret == -1)
		perror("Error");

}


// _PROC_RESOURCE/_PROC_RESOURCE_SETABILITIES
// TODO: Fix this.
void fuzz_proc_resource_setabilities()
{
	proc_resource_setabilities_t msg;
	int ret =  -1;

	msg.i.type = _PROC_RESOURCE;
	msg.i.subtype = _PROC_RESOURCE_SETABILITIES;
	msg.i.pid = rand();
	msg.i.count = rand();
	//msg.i.entry[0] = 2;


	ret = MsgSendnc(PROCMGR_COID, &msg.i, sizeof msg.i, 0, 0);

	printf("_PROC_RESOURCE_SETABILITIES ret = %d\n",ret);
	if (ret == -1)
		perror("Error");
}

#ifndef QNX65
// _PROC_VALUE (Undocumented).
void fuzz_proc_value()
{
	proc_value_t msg;
	int ret = -1;


	msg.i.type = _PROC_VALUE;
	msg.i.subtype = 0;


	msg.i.value = rand(); 								// 64bit
	msg.i.vtype = rand(); 								// 32bit value (undocumented limits)

	ret = MsgSendnc(PROCMGR_COID, &msg.i, sizeof msg.i, 0, 0);

	printf("_PROC_VALUE ret = %d\n",ret);
	if (ret == -1)
		perror("Error");

}


// _PROC_TIMER_TOLERANCE
void fuzz_proc_timer_tolerance()
{
	int ret = -1;
	proc_timer_tolerance_t msg;

	msg.i.type = _PROC_TIMER_TOLERANCE;
	msg.i.subtype = rand() % 2;

	msg.i.pid = rand();
	msg.i.tolerance = rand(); 								//64bit value

	ret = MsgSendnc(PROCMGR_COID, &msg.i, sizeof msg.i, 0, 0);

	printf("_PROC_TIMER_TOLERANCE ret = %d\n",ret);
	if (ret == -1)
		perror("Error");

}

#endif


// End of memmgr functions

#define _CONF_STR				(0x1U << 20)	/* Only use entry if checking for string */
#define _CONF_NUM				(0x2U << 20)	/* Only use entry if checking for number */
#define _CONF_COND_MASK			(0xfU << 20)

// Set does a permissions check
void fuzz_sysconf()
{
	sys_conf_t				msg;
	int name = 0;
	_Int64t value = 0;

	msg.i.type = _SYS_CONF;
	msg.i.subtype = rand() % 2;
	msg.i.cmd = rand();
	msg.i.name = rand();
	msg.i.value = rand();

	if(MsgSendnc_r(SYSMGR_COID, &msg.i, sizeof msg.i, &msg.o, sizeof msg.o) == -1) {
		perror("_SYS_CONF");
	}
}

void fuzz_syslog()
{

	sys_log_t	log;

	//len = MsgSendv(SYSMGR_COID, iov, nparts + 1, 0, 0);
}

// _SYS_VENDOR
void fuzz_sysvendor()
{
	sys_vendor_t msg;

	msg.i.type = _SYS_VENDOR;
	msg.i.vendor_id = rand();
	msg.i.reserved = rand();

	if(MsgSendnc_r(SYSMGR_COID, &msg.i, sizeof msg.i, 0, 0)) {
		perror("_SYS_VENDOR");
	}
	else
	{
		printf("fuzz_sysvendor: ok");
	}
}

void fd_fuzz(int fd)
{
	int sock;

	if (rand() % 2 == 0)
		sock = socket(rand(),rand(),rand());
	else
		sock = fd;

	if (sock == -1) return;

	int ret = -1;
	ioctl_socket(sock,rand());

	ret = setsockopt(sock,rand(),rand(),rand(),rand());
	if (ret == -1)
		perror("setsockopt");

	close(sock);
}

void devctl_fuzz(int fd)
{
	int ret = -1;

	ret = devctl(fd,rand(),rand(),rand(),rand());
	if (ret == -1) perror("devctl");

	fd_fuzz(fd);

	close(fd);
}

void file_fuzz()
{
	DIR *dp;
	struct dirent *ep;


	dp = opendir ("/dev/socket");


	if (dp != NULL)
	{
		while (ep = readdir (dp))
		{
			if ((rand() % 10) == 0)
				break;
		}
	    (void) closedir (dp);
	}



	char buf[256];
	memset(buf,0,256);

	strcpy(buf,"/dev/socket/");

	if (ep)
		strcat(buf,ep->d_name);

	if (strstr(buf,"tty") != 0) return;



	int fd = open(buf,rand() % 2);

	if (fd != -1)
		printf("devctl fuzzing %s\n", buf);
		devctl_fuzz(fd);
}

#define PATHMGR_COID			SYSMGR_COID

void connect_fuzz()
{
	//extern int _connect(int __base, const char *__path, mode_t __mode, unsigned __oflag, unsigned __sflag, unsigned __subtype, int __testcancel, unsigned __access, unsigned __file_type, unsigned __extra_type, unsigned __extra_len, const void *__extra, unsigned __response_len, void *__response, int *__status);

	char *path = "test";

	int fd = -1;

	int subtype = rand() % 11;
	int extra = rand() % 12;
	int testcancel = 0;
	unsigned int filetype = 0;
	int len = rand();

	char buf[256];


	fd = _connect(PATHMGR_COID, path, 0, O_CREAT | O_EXCL | O_NOCTTY, SH_DENYNO, subtype, testcancel, 0, filetype,0, 0,0, 0, 0, 0);

	if (fd == -1)
		perror("connect");

}

// TODO: Add ThreadCreate Stuff
int main(int argc, char *argv[]) {

	int ret = -1;
	int i, j = 0;

	srand(time(NULL));
	
	while (1) {

	// Procmgr calls
	fuzz_proc_spawn();
	fuzz_proc_spawnfd();
	fuzz_proc_spawn_done(); 	// not implemented
	fuzz_proc_spawn_debug();  // not implemented
	fuzz_proc_wait();
	//fuzz_proc_fork();
	fuzz_proc_getsetid();
	fuzz_proc_setpgid();
	fuzz_proc_umask();
	fuzz_proc_guardian();
	fuzz_proc_session();
	fuzz_proc_daemon();
	fuzz_proc_event();


	fuzz_proc_resource_getlimit();
	fuzz_proc_resource_usage();
	fuzz_proc_resource_usage();
	fuzz_proc_posix_spawn(); // broken

	#ifndef QNX65
	fuzz_proc_resource_setabilities();
	fuzz_proc_resource_lookupability();
	fuzz_proc_value();
	fuzz_proc_timer_tolerance();
	#endif


	fuzz_memmgr_offset();
	fuzz_memmgr_peer();
	fuzz_memmgr_ctrl();
	fuzz_memmgr_map();
	fuzz_memmgr_pmem_add();
	fuzz_memmgr_swap();

	}


	

/**	

	

	fuzz_sysvendor();
	fuzz_sysconf();
**/

//	file_fuzz();

//	}


	//fuzz_spawn_fd();
	//fuzz_spawn_args();



	//fuzz_proc_spawn();



	return EXIT_SUCCESS;
}
