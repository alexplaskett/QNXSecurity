
// ARM
// $env:QNX_HOST="C:\bbndk\host_10_3_1_29\win32\x86"
// $env:QNX_TARGET="C:\bbndk\target_10_3_1_2243\qnx6"
// C:\bbndk\host_10_3_1_29\win32\x86\usr\bin\ntoarmv7-gcc.exe .\syscall_fuzz.c -o syscall_fuzz -marm
// X86: 
// C:\bbndk\host_10_3_1_29\win32\x86\usr\bin\ntox86-gcc.exe .\syscall_fuzz.c -o syscall_fuzz -w
// Native code for fuzzing syscalls

// TODO: Add support for QNX 6.5/8.0
// Add Msg support

#include <sys/neutrino.h>
#include <sys/asyncmsg.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#include <unistd.h>

// Global vars

int chids[256]; // max of 256 channels 
int chid_count = 0;

sync_t sync2;

clockid_t id;
struct sigevent notify;
timer_t timerid;
struct _itimer itime;
struct _itimer otime;

int coid = 0;
int rcvid = 0;

#define QNX80
#define ARM

#ifdef QNX80
nto_job_t job;
#endif

// Taken from trinity
#define RAND_BYTE()             (rand() & 0xff)

static unsigned int plus_minus_two(unsigned int num)
{
    /* Now munge it for off-by-ones. */
    switch (rand() % 4) {
    case 0: num -= 2;
        break;
    case 1: num -= 1;
        break;
    case 2: num += 1;
        break;
    case 3: num += 2;
        break;
    }
    return num;
}

static unsigned char get_interesting_8bit_value(void)
{
    switch (rand() % 5) {
    case 0: return 1;                   // one
    case 1: return 0xff;                // max
    case 2: return 1UL << (rand() & 7); // 2^n (1 -> 128)
    case 3: return RAND_BYTE();         // 0 -> 0xff
    default: return 0;                  // zero
    }
}

static unsigned short get_interesting_16bit_value(void)
{
    switch (rand() % 4) {
    case 0: return 0x8000 >> (rand() & 7);      // 2^n (0x100 -> 0x8000)
    case 1: return rand() & 0xffff;             // 0 -> 0xffff
    case 2: return 0xff00 | RAND_BYTE();        // 0xff00 -> 0xffff
    default: return 0xffff;                     // max
    }
}

static unsigned int get_interesting_32bit_value(void)
{
    switch (rand() % 10) {
    case 0: return 0x80000000 >> (rand() & 0x1f);   // 2^n (1 -> 0x10000)
    case 1: return rand();                          // 0 -> RAND_MAX (likely 0x7fffffff)
    case 2: return (unsigned int) 0xff << (4 * (rand() % 7));
    case 3: return 0xffff0000;
    case 4: return 0xffffe000;
    case 5: return 0xffffff00 | RAND_BYTE();
    case 6: return 0xffffffff - 4096;
    case 7: return 4096;
    case 8: return 4096 * ((rand() % (0xffffffff/4096)) + 1);
    default: return 0xffffffff;                     // max
    }
}

unsigned long get_interesting_value(void)
{
    unsigned long low = 0;

    switch (rand() % 3) {
    case 0: low = get_interesting_8bit_value();
        break;
    case 1: low = get_interesting_16bit_value();
        break;
    case 2: low = get_interesting_32bit_value();
        break;
    }

    low = (rand() & 0xf) ? low : plus_minus_two(low);   // 1 in 16 call plus_minus_two
    return low;
}

void init()
{
	memset(chids,0,256);

	// Create a bunch of channels.
	int i = chid_count;
	while (chid_count < 10)
	{
		test_channel_create_ext();
	}
	printf("Init channels created\n");
	for (i = 0; i < 10; i++)
	{
		printf("chid = %d\n",chids[i]);
	}
}

int get_chid()
{
	if (chid_count == 0) return 0;

	if (chid_count > 200)
	{
		chid_count = 0;
		return 0;
	}

	printf("chid count = %d\n",chid_count);
	unsigned int idx = (rand() % chid_count);
	printf("chid idx = %d\n",idx);

	printf("++ Returning chid idx %d %d\n",idx, chids[idx]);
	int value = chids[idx];
	return value;
}


void add_chid(int chid)
{
	int idx = chid_count % 256;
	chids[idx] = chid;
	chid_count += 1;
	printf("++ Adding chid %d\n",chid);
}


unsigned char chance(int r)
{
	if (rand() % r == 0)
		return 1;
	else
		return 0;
}

// __KER_TRACE_EVENT
void test_traceevent()
{
	int ret = 0;
	int a0 = ((0x00000001<<28)| (rand() % 44));
	int a1 = rand() % 20;
	int a2 = get_interesting_32bit_value();
	int a3 = get_interesting_32bit_value();
	int a4 = get_interesting_32bit_value();
	printf("TraceEvent(%d,%d,%d,%d,%d);\n",a0,a1,a2,a3,a4);
	ret = TraceEvent(a0,a1,a2,a3,a4);
	printf("TraceEvent ret = %d\n",ret);
}

void test_func()
{
	printf("++ Callback fired ++");
}

// __KER_RING0
void test_ring0()
{
	int ret = 0;
	ret = __Ring0(test_func,0);
	printf("__Ring0 ret = %d\n",ret);
}

// __KER_CACHE_FLUSH
void test_cache_flush()
{
	int ret = 0;
	printf("CacheFlush();\n");
	ret = CacheFlush();
	printf("CacheFlush ret = %d\n",ret);
}

// __KER_SYS_CPUPAGE_GET
void test_sys_cpupage_get()
{
	int ret = 0;
	ret = __SysCpupageGet(1);
	printf("__SysCpupageGet ret = %d\n",ret);
}

// __KER_SYS_CPUPAGE_SET
void test_sys_cpupage_set()
{
	int idx = rand() % 8;
	int ret = 0;
	int value = get_interesting_32bit_value();
	printf("__SysCpupageSet(%d,%d);\n",idx,value);
	ret = __SysCpupageSet(idx,value);
}

//// __KER_MSG Calls ////

// __KER_MSG_PAUSE




///////////////////////// Channels /////////////////////////////////////////////////////////

void test_channel_create()
{
	unsigned flags = 0;
	int ret = 0;

	flags = get_interesting_16bit_value();

	printf("ChannelCreate(%d);\n",flags);
	ret = ChannelCreate(flags);
	printf("ChannelCreate ret = %d\n",ret);

	// Store the id's of created channels
	if (ret != -1)
		add_chid(ret);

}


// extern int ChannelCreateExt(unsigned __flags, mode_t __mode, size_t __bufsize, unsigned __maxnumbuf, const struct sigevent *__ev, struct _cred_info *__cred);
void test_channel_create_ext()
{
	unsigned flags = 0;
	mode_t mode = 666;
	size_t bufsize = 1024;
	unsigned __maxnumbuf = 1024;
	const struct sigevent ev;
	struct _cred_info cred;

	flags = get_interesting_16bit_value();
	mode = get_interesting_16bit_value();
	bufsize = get_interesting_32bit_value();
	__maxnumbuf = get_interesting_32bit_value();

	int ret = 0;

	if (chance(4))
	{
		int bad = get_interesting_32bit_value();
		printf("ChannelCreateExt(%d,%d,%d,%d,%x,%x);\n",flags,mode,bufsize,__maxnumbuf,&ev,&cred);
		ret = ChannelCreateExt(flags,mode,bufsize,__maxnumbuf,bad,bad);
	} 
	else
	{
		printf("ChannelCreateExt(%d,%d,%d,%d,%x,%x);\n",flags,mode,bufsize,__maxnumbuf,&ev,&cred);
		ret = ChannelCreateExt(flags,mode,bufsize,__maxnumbuf,&ev,&cred);
	}
	
	printf("ChannelCreateExt ret = %d\n",ret);
	if (ret != -1)
		add_chid(ret);
}

void test_channel_destroy()
{
	int ret = 0;
	int chid = get_chid();
	printf("ChannelDestroy(%d);\n",chid);
	ret = ChannelDestroy(ret);
	printf("ChannelDestroy ret = %d\n",ret);
}

// Should store the return value as coid.
// extern int ConnectAttach(_Uint32t __nd, pid_t __pid, int __chid, unsigned __index, int __flags);
void test_connect_attach()
{
	_Uint32t nd = 0;
	pid_t pid = 0;
	int chid = get_chid();
	unsigned index = get_interesting_16bit_value();
	int flags = get_interesting_16bit_value();
	int ret = 0;

	printf("ConnectAttach(%d,%d,%d,%d,%d);\n",nd,pid,chid,index,flags);

	ret = ConnectAttach(nd,pid,chid,index,flags);
	printf("ConnectAttach ret = %d\n",ret);
	if (ret != -1)
		coid = ret; 
}

// extern int ConnectAttachExt(_Uint32t __nd, pid_t __pid, int __chid, unsigned __index, int __flags, struct _asyncmsg_connection_descriptor *__cd);
void test_connect_attach_ext()
{
	_Uint32t nd = 0;
	pid_t pid = 0;
	int chid = get_chid();
	unsigned index = get_interesting_16bit_value();
	int flags = get_interesting_16bit_value();
	int ret = 0;

	struct _asyncmsg_connection_descriptor cd;
	memset(&cd,0,sizeof(struct _asyncmsg_connection_descriptor));

	if (chance(4))
	{
		int bad = get_interesting_32bit_value();
		printf("ConnectAttachExt(%d,%d,%d,%d,%d,%x);\n",nd,pid,chid,index,flags,bad);
		ret = ConnectAttachExt(nd,pid,chid,index,flags,&cd);
		printf("ConnectAttachExt ret = %d\n",ret);		
	}
	else
	{
		printf("ConnectAttachExt(%d,%d,%d,%d,%d,%x);\n",nd,pid,chid,index,flags,&cd);
		ret = ConnectAttachExt(nd,pid,chid,index,flags,&cd);
		printf("ConnectAttachExt ret = %d\n",ret);		
	}
	if (ret != -1)
		coid = ret; 
}

void test_connect_detach()
{
	int ret = 0;
	int chid = get_chid();
	printf("ConnectDetach(%d);\n",chid);
	ret = ConnectDetach(chid);
	printf("ConnectDetach ret = %d\n",ret);			
}

// extern int ConnectServerInfo(pid_t __pid, int __coid, struct _server_info *__info);
void test_connect_server_info()
{
	int ret = 0;
	int pid = 0;	
	struct _server_info info;

	if (chance(4))
	{
		int bad = get_interesting_32bit_value();
		printf("ConnectServerInfo(%d,%d,%x);\n",pid,coid,bad);
		ret = ConnectServerInfo(pid,coid,&info);
		printf("ConnectServerInfo ret = %d\n",ret);		
	}
	else
	{
		printf("ConnectServerInfo(%d,%d,%x);\n",pid,coid,&info);
		ret = ConnectServerInfo(pid,coid,&info);
		printf("ConnectServerInfo ret = %d\n",ret);			
	}
}

// extern int ConnectClientInfo(int __scoid, struct _client_info *__info, int __ngroups);
void test_connect_client_info()
{
	int scoid = coid;
	struct _client_info info;
	int ngroups = get_interesting_32bit_value();
	int ret = 0;

	if (chance(4))
	{
		int bad = get_interesting_32bit_value();
		printf("ConnectClientInfo(%d,%x,%d);\n",scoid,bad,ngroups);
		ret = ConnectClientInfo(scoid,&info,ngroups);
		printf("ConnectClientInfo ret = %d\n",ret);		
	}
	else
	{
		printf("ConnectClientInfo(%d,%x,%d);\n",scoid,&info,ngroups);
		ret = ConnectClientInfo(scoid,&info,ngroups);
		printf("ConnectClientInfo ret = %d\n",ret);			
	}
}

// extern int ConnectFlags(pid_t __pid, int __coid, unsigned __mask, unsigned __bits);
void test_connect_flags()
{
	int ret = 0;
	int pid = 0;	
	unsigned mask = get_interesting_32bit_value();
	unsigned bits = get_interesting_32bit_value();

	printf("ConnectFlags(%d,%d,%d,%d);\n",pid,coid,mask,bits);
	ret = ConnectFlags(pid,coid,mask,bits);
	printf("ConnectFlags ret = %d\n",ret);		
}

// extern int ChannelConnectAttr(unsigned __id, union _channel_connect_attr *__old_attr, union _channel_connect_attr *__new_attr, unsigned __flags);

void test_channel_connect_attr()
{
	unsigned id = 0;
	union _channel_connect_attr old_attr;
	union _channel_connect_attr new_attr;
	unsigned flags = get_interesting_32bit_value();
	int ret = 0;

	memset(&old_attr,0,sizeof(union _channel_connect_attr));
	memset(&new_attr,0,sizeof(union _channel_connect_attr));

	old_attr.flags = get_interesting_32bit_value();
	old_attr.bufsize = get_interesting_16bit_value();
	old_attr.maxbuf = get_interesting_16bit_value();
	old_attr.num_curmsgs = get_interesting_32bit_value();

	new_attr.flags = get_interesting_32bit_value();
	new_attr.bufsize = get_interesting_16bit_value();
	new_attr.maxbuf = get_interesting_16bit_value();
	new_attr.num_curmsgs = get_interesting_32bit_value();

	if (chance(4))
	{
		int bad =get_interesting_32bit_value();
		int bad2 = get_interesting_32bit_value();
		printf("ChannelConnectAttr(%d,%x,%x,%d);\n",id,bad,bad2,flags);
		ret = ChannelConnectAttr(id,&old_attr,&new_attr,flags);
		printf("ChannelConnectAttr ret = %d\n",ret);		
	}	
	else
	{
		printf("ChannelConnectAttr(%d,%x,%x,%d);\n",id,&old_attr,&new_attr,flags);
		ret = ChannelConnectAttr(id,&old_attr,&new_attr,flags);
		printf("ChannelConnectAttr ret = %d\n",ret);			
	}
}

#ifdef QNX80
// extern int ConnectClientInfoAble(int __scoid, struct _client_info **__info_pp, int flags, struct _client_able * const abilities, const int nable);
void test_connect_client_info_able()
{
	int scoid = coid;
	struct _client_info info;

	struct _client_info * info_p = &info;

	int flags = get_interesting_32bit_value();
	struct _client_able const abilities;
	const int nable = get_interesting_32bit_value();
	int ret = 0;


	printf("ConnectClientInfoAble(%d,%x,%d,%x,%d);\n",scoid,&info_p,flags,&abilities,nable);
	ret = ConnectClientInfoAble(scoid,&info_p,flags,&abilities,nable);

	printf("ConnectClientInfoAble ret = %d\n",ret);
}


// extern int ConnectClientInfoExt(int __scoid, struct _client_info **__info_pp, int flags);
void test_connect_client_info_ext()
{
	int scoid = coid;
	struct _client_info info;
	struct _client_info * info_p = &info;	
	int flags = get_interesting_32bit_value();	
	int ret = 0;

	printf("ConnectClientInfoExt(%d,%x,%d);\n",scoid,&info_p,flags);
	ret = ConnectClientInfoExt(scoid,&info_p,flags);
	printf("ConnectClientInfoExt ret = %d\n",ret);
}

// extern int ClientInfoExtFree(struct _client_info **__info_pp);
void test_connect_client_info_ext_free()
{
	struct _client_info info;
	struct _client_info * info_p = &info;	
	int ret = 0;
	ret = ClientInfoExtFree(&info_p);
	printf("ClientInfoExtFree ret = %d\n",ret);
}

#else
void test_connect_client_info_able()
{
	printf("null func\n");
}

void test_connect_client_info_ext()
{
	printf("null func\n");
}

void test_connect_client_info_ext_free()
{
	printf("null func\n");
}
#endif

void test_signal_return()
{
	int ret = 0;
	struct _sighandler_info info;
	info.handler = test_func;

	// This causes a crash on the simulator.
	//info.context = test_func;

	ret = SignalReturn(&info);
	printf("SignalReturn ret = %d\n",ret);
	if (ret == -1) perror("SignalReturn");
}

// __KER_SIGNAL_FAULT
// extern int SignalFault(unsigned __sigcode, void *__regs, _Uintptrt __refaddr);
void test_signal_fault()
{
	int sigcode = get_interesting_32bit_value();
	int ret = 0;
	char buf[256];
	memset(buf,0x41,256);

	// This will crash at register location on return to userspace.
	ret = SignalFault(sigcode,&buf,0);
	printf("SignalFault ret = %d\n",ret);
}

// extern int SignalAction(pid_t __pid, void (*__sigstub)(void), int __signo, const struct sigaction *__act, struct sigaction *__oact);
void test_signal_action()
{
	int pid = 1;
	int ret = 0;

	void *sigstub = test_func;
	int signo = rand() % 60;

	const struct sigaction act;
	const struct sigaction nact;

	ret = SignalAction(pid,sigstub,signo,&act,&nact);
	printf("SignalAction ret = %d\n",ret);
	perror("SignalAction");
}

// __KER_SIGNAL_PROCMASK
// SignalProcmask(pid_t __pid, int __tid, int __how, const sigset_t *__set, sigset_t *__oldset);
void test_signal_procmask()
{
	int pid = 1;
	int tid = 0;
	int _how = 0;
	int ret = 0;
	const sigset_t set;
	const sigset_t oldset;
	ret = SignalProcmask(pid,tid,_how,&set,&oldset);
	printf("SignalProcmask ret = %d\n",ret);
	perror("SignalProcmask");	
}

// __KER_SIGNAL_SUSPEND
// extern int SignalSuspend(const sigset_t *__set);
void test_signal_suspend()
{
	const sigset_t set;
	int ret = 0;
	ret = SignalSuspend(&set);
	printf("SignalSuspend ret = %d\n",ret);
	perror("SignalSuspend");	
}

//extern int SignalWaitinfo(const sigset_t *__set, siginfo_t *__info);
void test_signal_waitinfo()
{
	const sigset_t set;
	int ret = 0;
	ret = SignalWaitinfo(&set, &set);
	printf("SignalWaitinfo ret = %d\n",ret);
	perror("SignalWaitinfo");	
}

/////////////////////////////////// Sync Types ////////////////////////////////////////////

// extern int SyncTypeCreate(unsigned __type, sync_t *__sync, const struct _sync_attr *__attr);

void test_sync_type_create()
{
	unsigned type = rand() % 3;
	
	struct _sync_attr attr;
	int ret = 0;

	memset(&attr,0,sizeof(struct _sync_attr));
	attr.__protocol = 1;

	if (chance(4))
	{
		int bad = get_interesting_32bit_value();
		printf("SyncTypeCreate(%d,%x,%x);\n",type,bad,bad);
		ret = SyncTypeCreate(type,&sync2,&attr);
		printf("SyncTypeCreate ret = %d\n",ret);
	}
	else
	{
		printf("SyncTypeCreate(%d,%x,%x);\n",type,&sync2,&attr);
		ret = SyncTypeCreate(type,&sync2,&attr);
		printf("SyncTypeCreate ret = %d\n",ret);		
	}
}

void test_sync_destroy()
{
	int ret = 0;
	printf("SyncDestroy()\n");
	if (chance(4))
	{
		int bad = get_interesting_32bit_value();
		ret = SyncDestroy(bad);
		printf("SyncDestroy ret = %d\n",ret);
	}
	else
	{
		ret = SyncDestroy(&sync2);
		printf("SyncDestroy ret = %d\n",ret);
	}
}

void test_syncctl()
{
	int ret = 0;
	int cmd = get_interesting_32bit_value();
	if (cmd == 1) return;
	char buf[256];
	memset(buf,0x41,256);

	if (chance(4))
	{
		int bad = get_interesting_32bit_value();
		printf("SyncCtl(%d,%x,%x);\n",cmd,bad,bad);
		ret = SyncCtl(cmd,&sync2,&buf);
		printf("SyncCtl ret = %d\n",ret);
	}
	else
	{
		printf("SyncCtl(%d,%x,%x);\n",cmd,&sync2,&buf);
		ret = SyncCtl(cmd,&sync2,&buf);
		printf("SyncCtl ret = %d\n",ret);
	}
}

void test_sync_mutex_event()
{
		int ret = 0;
		struct sigevent event;

		if (chance(4))
		{
			int bad = get_interesting_32bit_value();
			printf("SyncMutexEvent();\n");
			ret = SyncMutexEvent(bad,bad);
			printf("SyncMutexEvent ret = %d\n",ret);			
		}
		else
		{
			printf("SyncMutexEvent();\n");
			ret = SyncMutexEvent(&sync2,&event);
			printf("SyncMutexEvent ret = %d\n",ret);		
		}


}

void test_sync_mutex_lock()
{
	int ret = 0;
	printf("SyncMutexLock();\n");
	ret = SyncMutexLock(&sync2);
	printf("SyncMutexLock ret = %d\n",ret);	
}

void test_sync_mutex_unlock()
{
	int ret = 0;
	printf("SyncMutexUnlock();\n");
	ret = SyncMutexUnlock(&sync2);
	printf("SyncMutexUnlock ret = %d\n",ret);	
}

void test_sync_mutex_revive()
{
	// sometimes use bad values.

	char buf[256];
	memset(buf,0,256);
	int ret = 0;

	if (chance(4))
	{
		buf[0] = get_interesting_32bit_value();
		buf[1] = get_interesting_32bit_value();
		buf[2] = get_interesting_32bit_value();
		int ret = 0;
		printf("SyncMutexRevive(%x);\n",&buf);
		ret = SyncMutexRevive(&sync2);
		printf("SyncMutexRevive ret = %d\n",ret);
	}
	else
	{
		printf("SyncMutexRevive(%x);\n",&sync2);
		ret = SyncMutexRevive(&sync2);
		printf("SyncMutexRevive ret = %d\n",ret);
	}


		
}

void change_sync_stuff()
{
	//sync.__u.__count = get_interesting_32bit_value();
	sync2.__owner = get_interesting_32bit_value();
}


// Interupt Stuff
// extern int InterruptHookTrace(const struct sigevent *(*__handler)(int), unsigned __flags);
void test_int_hook_trace()
{
	int ret =0; 
	ret = InterruptHookTrace(test_func,0);
	printf("InterruptHookTrace ret = %d\n",ret);
	if (ret == -1)
		perror("InterruptHookTrace");
}

void test_int_hook_idle()
{
	int ret =0; 
	ret = InterruptHookIdle(test_func,0);
	printf("InterruptHookIdle ret = %d\n",ret);
	if (ret == -1)
		perror("InterruptHookIdle");	
}

#ifdef QNX80
void test_int_hook_idle2()
{
	int ret =0; 
	ret = InterruptHookIdle2(test_func,0);
	printf("InterruptHookIdle2 ret = %d\n",ret);
	if (ret == -1)
		perror("InterruptHookIdle2");	
}
#endif

void test_int_attach()
{
	int r = get_interesting_8bit_value();
	const struct sigevent event;
	int ret =0; 
	ret = InterruptAttachEvent(r,&event,0);
	printf("InterruptAttachEvent ret = %d\n",ret);
	if (ret == -1)
		perror("InterruptAttachEvent");		
}

///////////////////////////////////// Thread Functions /////////////////////////////////////



// extern int ThreadCtl(int __cmd, void *__data);
void test_thread_ctl()
{
	int pid = 0;
	int ret = 0;

	int cmd = get_interesting_32bit_value();
	int data = get_interesting_32bit_value();

	printf("ThreadCtl(%d,%d);\n",cmd,data);
	ret = ThreadCtl(cmd,&data);
}

////////////////////////////////////////////////////////////////////////////////////////////
// Scheduler stuff

void test_sched_get()
{
	int pid = 0;
	int tid = 0;
	int ret = 0;
	struct sched_param param;

	if (chance(4))
	{
		int bad = get_interesting_32bit_value();
		printf("SchedGet(%d,%d,%x);\n",pid,tid,bad);
		ret = SchedGet(pid,tid,&param);
	}
	else
	{
		printf("SchedGet(%d,%d,%x);\n",pid,tid,&param);
		ret = SchedGet(pid,tid,&param);
	}

}

void test_sched_set()
{
	int pid = 0;
	int tid = 0;
	int ret = 0;
	int algorithm = rand() % 8;
	struct sched_param param;

	if (chance(4)) 
	{
		int bad = get_interesting_32bit_value();
		printf("SchedSet(%d,%d,%d,%x);\n",pid,tid,algorithm,bad);
		ret = SchedGet(pid,tid,&param);
	}
	else
	{
		printf("SchedSet(%d,%d,%d,%x);\n",pid,tid,algorithm,&param);
		ret = SchedGet(pid,tid,&param);		
	}
}

void test_sched_info()
{
	int pid = 0;
	int tid = 0;
	int ret = 0;
	int algorithm = get_interesting_32bit_value();
	struct _sched_info info;

	if (chance(4))
	{
		int bad = get_interesting_32bit_value();
		printf("SchedInfo(%d,%d,%x);\n",pid,algorithm,bad);
		ret = SchedInfo(pid,algorithm,&info);
	}
	else
	{
		printf("SchedInfo(%d,%d,%x);\n",pid,algorithm,&info);
		ret = SchedInfo(pid,algorithm,&info);		
	}
}

void test_sched_yield()
{
	int ret = 0;
	printf("SchedYield();\n");
	ret = SchedYield();
}

void test_sched_ctl()
{
	int cmd = 0;
	char data[256];
	data[0] = get_interesting_8bit_value();
	data[1] = get_interesting_8bit_value();
	data[2] = get_interesting_8bit_value();
	data[3] = get_interesting_8bit_value();
	int length = get_interesting_32bit_value();
	int ret = 0;

	if (chance(4))
	{
		int bad = get_interesting_32bit_value();
		printf("SchedCtl(%d,%x,%d);\n",cmd,bad,length);
		ret = SchedCtl(cmd,bad,length);	
	}
	else
	{
		printf("SchedCtl(%d,%x,%d);\n",cmd,&data,length);
		ret = SchedCtl(cmd,&data,length);		
	}

}

#ifdef QNX80
void test_sched_job_create()
{
	int ret = 0;
	printf("SchedJobCreate(%x);\n",&job);
	ret = SchedJobCreate(&job);
}

void test_sched_job_destroy()
{
	int ret = 0;
	printf("SchedJobDestroy(%x);\n",&job);
	ret = SchedJobDestroy(&job);
}

// extern int SchedWaypoint(nto_job_t *__job, const _Int64t *__new, const _Int64t *__max, _Int64t *__old);
void test_sched_waypoint()
{
	_Int64t __new = get_interesting_32bit_value();
	_Int64t __old = get_interesting_32bit_value();
	_Int64t __max = get_interesting_32bit_value();
	int ret = 0;
	printf("SchedWaypoint(%x,%ul,%ul,%ul);\n",__new,__max,__old);
	ret = SchedWaypoint(&job,__new,__max,__old);
}

void test_sched_waypoint2()
{
	_Int64t __new = get_interesting_32bit_value();
	_Int64t __old = get_interesting_32bit_value();
	_Int64t __max = get_interesting_32bit_value();
	int ret = 0;
	printf("SchedWaypoint2(%x,%ul,%ul,%ul);\n",__new,__max,__old);
	ret = SchedWaypoint2(&job,__new,__max,__old);
}

#endif
//////////////////////////////// Timer Functions /////////////////////////////////////////

void test_timer_create()
{
	int ret = 0; 
	printf("TimerCreate(%d,%x);\n");
	timerid = TimerCreate(id,&notify);
}

void test_timer_destroy()
{
	int ret = 0;
	printf("TimerDestroy(%d,%x);\n");
	ret = TimerDestroy(timerid);
}

void test_settime()
{
	int flags = 0;
	int ret = 0;
	if (chance(4))
	{
		printf("TimerSettime(%d,%d,%x,%x);\n",timerid,flags,&itime,&itime);
		ret = TimerSettime(timerid,flags,&itime,&itime);
	}
	else
	{
		printf("TimerSettime(%d,%d,%x,%x);\n",timerid,flags,&itime,&otime);
		ret = TimerSettime(timerid,flags,&itime,&otime);
	}
}

void test_timerinfo()
{
	pid_t pid = 0;
	int flags = 0;
	struct _timer_info info;	
	info.itime = itime;
	info.otime = otime;
	info.tid = 0;
	info.notify = get_interesting_32bit_value();
	info.clockid = id;
	info.event = notify;
	int ret = 0;

	printf("TimerInfo(%d,%d,%d,%x);\n",pid,timerid,flags,&info);
	ret = TimerInfo(pid,timerid,flags,&info);
}

void test_timeralarm()
{
	int ret = 0;
	printf("TimerAlarm(%d,%x,%x);\n",timerid,&itime,&otime);
	ret = TimerAlarm(timerid,&itime,&otime);	
}

// extern int TimerTimeout(clockid_t __id, int __flags, const struct sigevent *__notify, const _Uint64t *__ntime, _Uint64t *__otime);
void test_timertimeout()
{
	int flags = 0;
	int ret = 0;
	_Uint64t ntime;
	_Uint64t notime;
	ret = TimerTimeout(id,flags,&notify,&ntime,&notime);
}

//////////////////////////////////// Clock Stuff ///////////////////////////////////////////

void test_clocktime()
{
	int ret = 0;
	_Uint64t _new;
	_Uint64t _old;
	
	if (chance(4))
	{
		int bad = get_interesting_32bit_value();
		printf("ClockTime(%d,%d,%d);\n",id,bad,bad);
		ret = ClockTime(id,bad,bad);
	}
	else
	{
		printf("ClockTime(%d,%x,%x);\n",id,&_new,&_old);
		ret = ClockTime(id,&_new,&_old);
	}
}

void test_clockadjust()
{
	struct _clockadjust _new;
	struct _clockadjust _old;
	int ret = 0;
	if (chance(4))
	{
		int bad = get_interesting_32bit_value();
		printf("ClockAdjust(%d,%d,%d);\n",id,bad,bad);
		ret = ClockAdjust(id,bad,bad);
	}
	else
	{
		printf("ClockAdjust(%d,%x,%x);\n",id,&_new,&_old);
		ret = ClockAdjust(id,&_new,&_old);
	}
}

void test_clockperiod()
{
	struct _clockperiod _new;
	struct _clockperiod _old;
	int ret = 0;
	int res = get_interesting_32bit_value();
	if (chance(4))
	{
		int bad = get_interesting_32bit_value();
		printf("ClockPeriod(%d,%d,%d,%d);\n",id,bad,bad,res);
		ret = ClockPeriod(id,bad,bad,res);
	}
	else
	{
		printf("ClockPeriod(%d,%x,%x,%d);\n",id,&_new,&_old,res);
		ret = ClockPeriod(id,&_new,&_old,res);
	}	
}

void test_clockid()
{
	int ret = 0;
	int pid = 0;
	int tid = 0;
	printf("ClockId(%d,%d);\n",pid,tid);
	ret = ClockId(pid,tid);
}

////////////////////////////////// Message Stuff ///////////////////////////////////////

void test_msgpause()
{
	int ret = 0;
	int cookie = 0;
	printf("MsgPause(%d,%d);\n",rcvid,cookie);
	ret = MsgPause(rcvid,cookie);
}

void test_msgcurrent()
{
	int ret = 0;
	printf("MsgCurrent(%d);\n",rcvid);
	ret = MsgCurrent(rcvid);
}

// extern int MsgSend(int __coid, const void *__smsg, int __sbytes, void *__rmsg, int __rbytes);
void test_msgsend()
{
	char buf[256];
	int ret = 0;
	int len = get_interesting_32bit_value();
	printf("MsgSend(%d,%x,%d,%x,%d);\n",coid,&buf,len,0,0);
	ret = MsgSend(coid,&buf,len,0,0);
}

void test_msgerror()
{
	int ret = 0;
	int e = get_interesting_32bit_value();
	printf("MsgError(%d,%d);\n",rcvid,e);
	ret = MsgError(rcvid,e);
}

// MsgWritev(int __rcvid, const struct iovec *__iov, int __parts, int __offset);
void test_msgwritev()
{
	int ret = 0;
	int parts = get_interesting_32bit_value();
	int offset = get_interesting_32bit_value();
	struct iovec				iov[2];
	char buf[256];

	SETIOV(&iov[0], &buf, get_interesting_32bit_value());
	SETIOV(&iov[1], &buf, get_interesting_32bit_value());

	printf("MsgWritev(%d,%x,%d,%d);\n",rcvid,iov,parts,offset);
	ret = MsgWritev(rcvid,iov,parts,offset);
}



//////////////////////////////////////////////////////////////////////////////////////////

// __KER_POWER_PARAMETER
// extern int PowerParameter(unsigned __id, unsigned __struct_len, 
// const struct nto_power_parameter *__new,
// struct nto_power_parameter *__old);

#ifdef QNX80
void test_pow_param()
{
	int id = get_interesting_32bit_value();
	struct nto_power_parameter n;
	struct nto_power_parameter o;
	int len = get_interesting_32bit_value();

	int ret = 0;
	printf("PowerParameter(%d,%d,%x,%x);\n",id,len,&n,&o);
	ret = PowerParameter(id,len,&n,&o);
	printf("PowerParameter ret = %d\n",ret);
}
#else
void test_pow_param()
{
}

#endif

void test_rawsyscall()
{
	int r0 = get_interesting_32bit_value() % 120;
	int r1 = get_interesting_32bit_value();
	int r2 = get_interesting_32bit_value();
	int r3 = get_interesting_32bit_value();
	int r4 = get_interesting_32bit_value();

	printf("syscall(%d,%d,%d,%d,%d);\n",r0,r1,r2,r3,r4);
	syscall(r0,r1,r2,r3,r4);
}

#ifdef ARM
__attribute__ ((naked)) void syscall(int callnum, ...)
{
	asm (
     	"STMFD  SP!, {LR}\n\t"
		"MOV R12, R0\n"
		" SVC 0x51\n"
		"ldmfd sp, {PC}"
		);
}

#else
// X86 version
void syscall(int callnum, ...)
{

}
#endif

void callback()
{
	printf("Callback fired!\n");
	void (*syscalls[])(void) = {

	 test_channel_create,
	 test_channel_create_ext, 
	 test_channel_destroy,
     test_connect_attach,
     test_connect_attach_ext,
     test_connect_server_info,
     test_connect_client_info,
     test_connect_flags,
     test_channel_connect_attr,
     //test_connect_client_info_able,
     //test_connect_client_info_ext,
     test_sys_cpupage_set,
    
     test_sync_type_create,
     test_sync_destroy,
     test_syncctl,
     test_sync_mutex_event,
     //test_sync_mutex_lock,
     change_sync_stuff,
     test_sync_mutex_unlock,
     test_sync_mutex_revive,
     test_int_hook_trace,
     test_int_hook_idle,
     //test_int_hook_idle2,
     test_int_attach,

     test_thread_ctl,
     test_sched_get,
     test_sched_set,
     test_sched_info,
     test_sched_yield,
     test_sched_ctl,
     //test_sched_job_create,
     //test_sched_job_destroy,
     //test_sched_waypoint,
     //test_sched_waypoint2,
     test_timer_create,
     test_timer_destroy,
     test_settime,
     test_timerinfo,
     test_timertimeout
	};

	int idx = rand() % 34;
	void (*syscall)() = syscalls[idx]; 
	syscall();

}


// extern int ThreadCreate(pid_t __pid, void *(*__func)(void *__arg), void *__arg, const struct _thread_attr *__attr);
void test_thread_create()
{
	int pid = 0;
	int ret = 0;

	struct _thread_attr attr;
	struct __sched_param sched;

	memset(&attr,0,sizeof(struct _thread_attr));

	attr.__flags = get_interesting_32bit_value();
	attr.__stacksize = get_interesting_32bit_value();
	attr.__stackaddr = get_interesting_32bit_value();
	//attr.__exitfunc = get_interesting_32bit_value();
	attr.__policy = get_interesting_32bit_value();
	attr.__guardsize = get_interesting_32bit_value();
	attr.__prealloc = get_interesting_32bit_value();

	printf("ThreadCreate(%d,%d,%d,%d,%d,%d,%d);\n",attr.__flags,attr.__stacksize,attr.__stackaddr,attr.__exitfunc,attr.__policy,attr.__guardsize,attr.__prealloc);
	ret = ThreadCreate(pid,&callback,0,&attr);

	ThreadJoin(ret,0);
}

void test_thread_destroy()
{
	int tid = 0;
	int priority = get_interesting_32bit_value();
	ThreadDestroy(tid,priority,0);
}

void null_func() { }

// List of syscalls to test
void (*syscalls[])(void) = {

	 test_channel_create,              	// 0
	 test_channel_create_ext, 			// 1
	 test_channel_destroy,				// 2
     test_connect_attach,				// 3
     test_connect_attach_ext,			// 4
     test_connect_server_info,			// 5
     test_connect_client_info,			// 6
     test_connect_flags,				// 7
     test_channel_connect_attr,			// 8
     test_connect_client_info_able,		// 9
     test_connect_client_info_ext,		// 10
     test_sys_cpupage_set,				// 11
    
     test_sync_type_create,				// 12
     test_sync_destroy,					// 13
     test_syncctl,						// 14
     test_sync_mutex_event,				// 15
     //test_sync_mutex_lock,			// 16
     null_func,							// 16
     change_sync_stuff,					// 17
     test_sync_mutex_unlock,			// 18
     test_sync_mutex_revive,			// 19
     test_int_hook_trace,				// 20
     test_int_hook_idle,				// 21
     test_int_hook_idle2,				// 22
     test_int_attach,					// 23

     test_thread_create,				// 24
     test_thread_ctl,					// 25
     test_sched_get,					// 26
     test_sched_set,					// 27
     test_sched_info,					// 28
     test_sched_yield,					// 29
     test_sched_ctl,					// 30
     test_sched_job_create,				// 31
     test_sched_job_destroy,			// 32
     test_sched_waypoint,				// 33
     test_sched_waypoint2,				// 34
     test_timer_create,					// 35
     test_timer_destroy,				// 36
     test_settime,						// 37
     test_timerinfo,					// 38
     test_timertimeout,					// 39
     test_traceevent,					// 40
     test_cache_flush,					// 41
     test_clocktime,					// 42
     test_clockadjust,					// 43
     test_clockperiod,					// 44
     test_clockid,						// 45

     test_pow_param,					// 46
     //test_rawsyscall,					// 47

     // Msg Stuff
     test_msgpause,						// 47
     //test_msgsend,						// 48
     test_msgcurrent,					// 49
     test_msgwritev,					// 50

	};


int main(int argc, char *argv[])
{
	printf("CSyscallFuzz\n");

	srand(time(0));
	init();

	int table_size = (sizeof(syscalls) / 4);
	printf("Syscall table size = %d\n",table_size);

	if (argc > 1) 
	{
		// for testing singular calls
		int idx = atoi(argv[1]);
		printf("index = %d\n",idx);
		while (1)
		{
			if (idx < 0 || idx > table_size-1)
			{
				printf("outside of syscall table!!\n");
				exit(1);
			}
			void (*syscall)() = syscalls[idx]; 
			syscall();
		}
	}
	else
	{
		while (1)
		{
			int idx = rand() % table_size;
			void (*syscall)() = syscalls[idx]; 
			syscall();
		}
	}

	return 0;
}