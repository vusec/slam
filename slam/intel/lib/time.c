/* Accurate timing functionality.
 *
 * Date: November 23, 2023
 * Author: Mathé Hertogh - Vrije Universiteit Amsterdam
 */

#include "slam.h"

static uint64_t timestamp;

void timer_init()
{
	// Nothing to do.
}

uint64_t time_access(volatile char *addr)
{
	unsigned start_low, start_high, end_low, end_high;
	uint64_t start, end, duration;

	asm volatile (
		"xor %%rax, %%rax\n\t"
		"cpuid\n\t"
		"rdtsc\n\t"
		"mov %%edx, %0\n\t"
		"mov %%eax, %1\n\t"
		"mov (%4), %%rcx\n\t"
		"rdtscp\n\t"
		"mov %%edx, %2\n\t"
		"mov %%eax, %3\n\t"
		"xor %%rax, %%rax\n\t"
		"cpuid\n\t"
		: "=&r" (start_high), "=&r" (start_low), "=r" (end_high), "=r" (end_low)
		: "r" (addr)
		: "%rax", "%rbx", "%rcx", "%rdx"
	);

	start = ((uint64_t)start_high << 32) | (uint64_t)start_low;
	end = ((uint64_t)end_high << 32) | (uint64_t)end_low;
	duration = end - start;

	return duration;
}

uint64_t time_prefetch(volatile char *addr)
{
	unsigned start_low, start_high, end_low, end_high;
	uint64_t start, end, duration;

	asm volatile (
		"xor %%rax, %%rax\n\t"
		"cpuid\n\t"
		"rdtsc\n\t"
		"mov %%edx, %0\n\t"
		"mov %%eax, %1\n\t"
		"prefetcht0 (%4)\n\t"
		"rdtscp\n\t"
		"mov %%edx, %2\n\t"
		"mov %%eax, %3\n\t"
		"xor %%rax, %%rax\n\t"
		"cpuid\n\t"
		: "=&r" (start_high), "=&r" (start_low), "=r" (end_high), "=r" (end_low)
		: "r" (addr)
		: "%rax", "%rbx", "%rcx", "%rdx"
	);

	start = ((uint64_t)start_high << 32) | (uint64_t)start_low;
	end = ((uint64_t)end_high << 32) | (uint64_t)end_low;
	duration = end - start;

	return duration;
}

void step_start()
{
	timestamp = clock_read();
}

void step_end()
{
	float duration = (float)(clock_read() - timestamp) / 1000000000.0;
	pr_info("Step took %.2f seconds.\n", duration);
}

uint64_t clock_read()
{
	struct timespec ts;
	clock_gettime(CLOCK_REALTIME, &ts);
	return ts.tv_sec * 1000000000 + ts.tv_nsec;
}
