
// $env:QNX_HOST="C:\bbndk\host_10_3_1_29\win32\x86"
// $env:QNX_TARGET="C:\bbndk\target_10_3_1_2243\qnx6"
// C:\bbndk\host_10_3_1_29\win32\x86\usr\bin\ntoarmv7-gcc.exe .\syscall_fuzz.c -o syscall_fuzz -marm
// Native code for fuzzing syscalls

#include <sys/neutrino.h>

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

// __KER_TRACE_EVENT
void test_traceevent()
{
	int ret = 0;
	ret = TraceEvent(1);
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
	//ret = CacheFlush();
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
	__SysCpupageSet(0,1);
	struct _process_local_storage		*pls;
	pls = __SysCpupageGet(1);
	printf("pls = %p\n",pls);
	__SysCpupageSet(1,0);
	pls = __SysCpupageGet(1);
	printf("pls = %p\n",pls);

}

//// __KER_MSG Calls ////

// __KER_MSG_PAUSE


// Signal syscalls
// SignalReturn(struct _sighandler_info *__info);

// 	struct kerargs_signal_return {
//		KARGSLOT(SIGSTACK 	*s);
//	} signal_return;

void test_signal_return()
{
	int ret = 0;
	struct _sighandler_info info;
	info.handler = test_func;

	// This causes a crash on the simulator.
	info.context = test_func;

	ret = SignalReturn(&info);
	printf("SignalReturn ret = %d\n",ret);
	if (ret == -1) perror("SignalReturn");
}

// __KER_SIGNAL_FAULT
// extern int SignalFault(unsigned __sigcode, void *__regs, _Uintptrt __refaddr);
void test_signal_fault()
{
	int sigcode = 0;
	int ret = 0;
	char buf[256];
	memset(buf,0,256);

	// This will crash at register location on return to userspace.
	ret = SignalFault(sigcode,&buf,0xffffffff);
	printf("SignalFault ret = %d\n",ret);
}

// extern int SignalAction(pid_t __pid, void (*__sigstub)(void), int __signo, const struct sigaction *__act, struct sigaction *__oact);
void test_signal_action()
{
	int pid = 0;
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
	int pid = 0;
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

///////////////////////// Channels /////////////////////////////////////////////////////////

// extern int ChannelCreateExt(unsigned __flags, mode_t __mode, size_t __bufsize, unsigned __maxnumbuf, const struct sigevent *__ev, struct _cred_info *__cred);
void test_channel_create()
{
	unsigned flags = 0;
	mode_t mode = 666;
	size_t bufsize = 1024;
	unsigned __maxnumbuf = 1024;
	const struct sigevent ev;
	struct _cred_info cred;

	int ret = 0;
	ret = ChannelCreateExt(flags,mode,bufsize,__maxnumbuf,&ev,&cred);
	printf("ChannelCreateExt ret = %d\n",ret);
	if (ret != -1)
	{
		printf("created channel\n");
	}
}

void test_channel_destroy()
{
	int ret = 0;
	int chid = 0;
	ret = ChannelDestroy(ret);
	printf("ChannelDestroy ret = %d\n",ret);
}

// __KER_POWER_PARAMETER
// extern int PowerParameter(unsigned __id, unsigned __struct_len, 
// const struct nto_power_parameter *__new,
// struct nto_power_parameter *__old);

void test_pow_param()
{
	int id = 0;
	struct nto_power_parameter n;
	struct nto_power_parameter o;
	int len = -1;

	int ret = 0;
	ret = PowerParameter(id,len,&n,&o);
	printf("PowerParameter ret = %d\n",ret);
	perror("PowerParameter");	
}

#ifdef ARM
__attribute__ ((naked)) void syscall_arm(int callnum, ...)
{
	asm (
     	"STMFD  SP!, {LR}\n\t"
		"MOV R12, R0\n"
		" SVC 0x51\n"
		"ldmfd sp, {PC}"
		);
}

#endif

void syscall_x86(int callnum, ...)
{

}

int main(int argc, char *argv[])
{
	printf("CSyscallFuzz\n");
	//srand(time(0));

	test_traceevent();
	test_ring0();
	test_cache_flush();
	test_sys_cpupage_get();
	test_sys_cpupage_set();

	// Signals
	//test_signal_return();
	//test_signal_fault();
	test_signal_action();
	test_signal_procmask();
	// test_signal_suspend(); - blocks
	//test_signal_waitinfo(); 

	// Channels
	test_channel_create();


	test_pow_param();


	//struct _process_local_storage		*pls;

	//pls = __SysCpupageGet(1);
	//printf("pls = %p\n",pls);

	//__SysCpupageSet(1,0);

	//pls = __SysCpupageGet(1);
	//printf("pls = %p\n",pls);


	/**
	int r0;
	int r1;
	int r2; 
	int r3; 
	int r4; 
	int r5; 
	int r6;
	int r7;

	while (1) 
	{
		// Syscall number (0-106)
		r0 = rand() % 106;
		if (r0 == 48 || r0 == 58 || r0 == 14 || r0 == 24)
		{
			r0 = 0;
		}
		printf("num = %d\n",r0);

		r1 = get_interesting_value();
		r2 = get_interesting_value();
		r3 = get_interesting_value();
		r4 = get_interesting_value();
		r5 = get_interesting_value();
		r6 = get_interesting_value();
		r7 = get_interesting_value();

		syscall_arm(r0,r1,r2,r3,r4,r5,r6,r7);
	}
	**/
}