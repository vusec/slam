/* Accurate timing functionality.
 *
 * Date: November 23, 2023
 * Author: Mathé Hertogh - Vrije Universiteit Amsterdam
 */

#include "slam.h"

static pid_t timer_thread;
static uint64_t *shared_page; // Shared page between main thread and timer thread.
static volatile uint64_t *timer; // Counter incremented by the timer thread.
static volatile uint64_t *stop; // Timer thread runs as long as !*stop.

__attribute__ ((noinline)) __attribute__((aligned(64)))
static void  timer_thread_loop()
{
	uint64_t count = 0;
	while (!*stop) {
		count++;
		*timer = count;
	}
}

static void timer_thread_main()
{
	if (prctl(PR_SET_PDEATHSIG, SIGTERM) == -1)
		fail("PR_SET_PDEATHSIG failed");

	set_cpu_affinity(get_sibling(CPU));

	timer_thread_loop();

	exit(EXIT_SUCCESS);
}

static pid_t spawn_timer_thread()
{
	*timer = 0;
	*stop = 0;

	pid_t pid = fork();
	if (pid == 0)
		timer_thread_main(stop);

	// Let the timer thread spin up.
	while (*timer < 1000);

	return pid;
}

void timer_init()
{
	pr_info("=====[timer init]=====\n");

	shared_page = mmap(NULL, PAGE_SIZE, PROT_RW, MAP_ANONYMOUS|MAP_SHARED|MAP_POPULATE, -1, 0);
	// Our TLB evict+reload uses the lower L1D cache sets. Let's use the
	// uppermost set for our (noisy) timer cache line.
	timer = shared_page + (PAGE_SIZE / sizeof(uint64_t) - 1);
	stop = timer - 1;
	timer_thread = spawn_timer_thread();
}

void timer_fini()
{
	// Terminate and reap the timer thread.
	*stop = 1;
	int status;
	assert(wait(&status) == timer_thread);

	munmap((void *)timer, PAGE_SIZE);
}

uint64_t time_access(volatile char *addr)
{
	/* Make sure timer is in the L1 TLB and L1D cache; our evictions may
	 * have evicted timer as well.
	 */
	*timer;

	cpuid();
	uint64_t start = *timer;
	lfence();

	*addr;

	lfence();
	uint64_t end = *timer;
	cpuid();

	return end - start;
}

uint64_t clock_read()
{
	struct timespec ts;
	clock_gettime(CLOCK_REALTIME, &ts);
	return ts.tv_sec * 1000000000 + ts.tv_nsec;
}
