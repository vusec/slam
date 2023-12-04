#include <linux/syscalls.h>
#include <linux/proc_fs.h>

MODULE_AUTHOR("Mathé Hertogh");
MODULE_DESCRIPTION("kslam: SLAM's kernel module");
MODULE_LICENSE("GPL");

static size_t u64_from_user(u64 *value, const char *buf, size_t *len, loff_t *off)
{
	char kbuf[32];
	memset(kbuf, 0, 32);

	*len = min(*len, sizeof(kbuf) - 1);
	if (copy_from_user(kbuf, buf, *len))
		return -1;
	if (sscanf(kbuf, "%llx", value) != 1)
		return -1;

	*off += *len;
	return 0;
}

static size_t u64_to_user(char __user *buf, size_t len, loff_t *off, u64 value)
{
	char kbuf[18];

	if (*off > 0)
		return 0;

	len = min(len, 18UL);
	snprintf(kbuf, len, "%16llx\n", value);
	if (copy_to_user(buf, kbuf, len))
		return -EFAULT;

	*off += len;
	return len;
}

noinline
static void unmasked_gadget(void *secret_ptr, u64 lam_mask)
{
	asm volatile (
			"call overwrite_arch_return_addr\n\t"
		"spec_return:\n\t"
			"movq (%0), %%rax\n\t"		// secret = *secret_ptr
			"and %%rbx, %%rax\n\n"		// lam_mask(secret)
			"movb (%%rax), %%al\n\t"	// *secret
		"infinite_loop:\n\t"
			"pause\n\t"
			"jmp infinite_loop\n\t"
		"overwrite_arch_return_addr:\n\t"
			"movq $arch_return, (%%rsp)\n\t"
			"clflush (%%rsp)\n\t"
			"cpuid\n\t"
			"movq %1, %%rbx\n\t"
			"ret\n\t"
		"arch_return:\n\t"
		:
		: "r" (secret_ptr), "r" (~lam_mask)
		: "%rax", "%rbx", "%rcx", "%rdx"
	);
}

static ssize_t gadget_write(struct file *filp, const char *buf, size_t len, loff_t *off)
{
	u64 secret_ptr;
	if (u64_from_user(&secret_ptr, buf, &len, off))
		return -EFAULT;
	// Native unmasked gadget, no masking at all.
	unmasked_gadget((void *)secret_ptr, 0x0);
	return len;
}

static ssize_t gadget_lam_write(struct file *filp, const char *buf, size_t len, loff_t *off)
{
	u64 secret_ptr;
	if (u64_from_user(&secret_ptr, buf, &len, off))
		return -EFAULT;
	// Intel's LAM masks the 15 bits 49-62.
	unmasked_gadget((void *)secret_ptr, 0x7fff000000000000);
	return len;
}

static ssize_t gadget_uai_write(struct file *filp, const char *buf, size_t len, loff_t *off)
{
	u64 secret_ptr;
	if (u64_from_user(&secret_ptr, buf, &len, off))
		return -EFAULT;
	// As we are on 4-level paging, we emulate AMD's UAI by masking the top 16 bits.
	unmasked_gadget((void *)secret_ptr, 0xffff000000000000);
	return len;
}

static ssize_t direct_map_read(struct file *filp, char __user *buf, size_t len, loff_t *off)
{
	return u64_to_user(buf, len, off, page_offset_base);
}

static u32 fineibt_sid;

static ssize_t fineibt_sid_read(struct file *filp, char __user *buf, size_t len, loff_t *off)
{
	return u64_to_user(buf, len, off, fineibt_sid);
}

static ssize_t fineibt_sid_write(struct file *filp, const char *buf, size_t len, loff_t *off)
{
	u64 new_sid;
	if (u64_from_user(&new_sid, buf, &len, off))
		return -EFAULT;
	fineibt_sid = new_sid;
	return len;
}

#define FINEIBT_MAX_CHAIN 10
#define FINEIBT_RELOAD_BUF ((void *)0x9797000)
static struct page *fineibt_pages[FINEIBT_MAX_CHAIN];
void **fineibt_chain[FINEIBT_MAX_CHAIN];
#define STR(X) STRR(X)
#define STRR(X) #X

static inline void serialize_cpuid(void)
{
	asm volatile (
		"xor %%rax, %%rax\n\t"
		"cpuid\n\t"
		::: "%rax", "%rbx", "%rcx", "%rdx"
	);
}

static void transient_load_chain(void **chain_start)
{
	asm volatile (
			"call setup\n\t"
		"fineibt_stub:\n\t" // Speculatively return here.
			"sub $0xcaca0, %%eax\n\t"
			"je gadget\n\t"
			"hlt\n\t"
		"gadget:\n\t"
			".rept " STR(FINEIBT_MAX_CHAIN) "\n\t"
				"movq (%%rbx), %%rbx\n\t"
			".endr\n\t"
			"hlt\n\t"
		"setup:\n\t"
			"movq $architectural_return, (%%rsp)\n\t"
			"clflush (%%rsp)\n\t"
			"mov %0, %%eax\n\t"
			"movq %1, %%rbx\n\t"
			"mfence\n\t"
			"lfence\n\t"
			"ret\n\t"
		"architectural_return:\n\t"
		:
		: "r" (fineibt_sid), "r" (chain_start)
		: "%rax", "%rbx", "%rcx", "%rdx"
	);
}

static ssize_t fineibt_gadget_write(struct file *filp, const char *buf, size_t len, loff_t *off)
{
	volatile void *p;
	u64 i, chain_len;
	if (u64_from_user(&chain_len, buf, &len, off))
		return -EFAULT;
	chain_len = (u64)min(max(1, (int)chain_len), FINEIBT_MAX_CHAIN);

	// Make sure the chain is hot, except the reload buffer at index 0.
	for (i = chain_len-1; i > 0; i--) {
		serialize_cpuid();
		p = *fineibt_chain[i];
	}
	serialize_cpuid();

	transient_load_chain(fineibt_chain[chain_len-1]);

	return len;
}

static void fineibt_init(void)
{
	int i;
	char *addr;
	
	fineibt_chain[0] = FINEIBT_RELOAD_BUF;
	for (i = 1; i < FINEIBT_MAX_CHAIN; i++) {
		fineibt_pages[i] = alloc_page(GFP_KERNEL);
		addr = page_address(fineibt_pages[i]);
		fineibt_chain[i] = (void **)(addr + PAGE_SIZE/2 + i*64);
		*fineibt_chain[i] = fineibt_chain[i-1];
	}
}

static struct proc_ops gadget_fops = {
	.proc_write = gadget_write,
};
static struct proc_ops gadget_lam_fops = {
	.proc_write = gadget_lam_write,
};
static struct proc_ops gadget_uai_fops = {
	.proc_write = gadget_uai_write,
};

static struct proc_ops direct_map_fops = {
	.proc_read = direct_map_read,
};

static struct proc_ops fineibt_sid_fops = {
	.proc_read = fineibt_sid_read,
	.proc_write = fineibt_sid_write,
};

static struct proc_ops fineibt_gadget_fops = {
	.proc_write = fineibt_gadget_write,
};

static struct proc_dir_entry *proc_dir;

static int __init kslam_init(void)
{
	pr_info("initializing\n");

	proc_dir = proc_mkdir("kslam", NULL);
	proc_create("gadget", 0222, proc_dir, &gadget_fops);
	proc_create("gadget_lam", 0222, proc_dir, &gadget_lam_fops);
	proc_create("gadget_uai", 0222, proc_dir, &gadget_uai_fops);
	proc_create("direct_map", 0444, proc_dir, &direct_map_fops);
	proc_create("fineibt_sid", 0666, proc_dir, &fineibt_sid_fops);
	proc_create("fineibt_gadget", 0666, proc_dir, &fineibt_gadget_fops);

	fineibt_init();

	return 0;
}

static void __exit kslam_exit(void)
{
	int i;
	pr_info("exiting\n");

	for (i = 1; i < FINEIBT_MAX_CHAIN; i++)
		__free_pages(fineibt_pages[i], 0);

	proc_remove(proc_dir);
}

module_init(kslam_init);
module_exit(kslam_exit);
