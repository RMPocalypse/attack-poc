// SPDX-License-Identifier: GPL-2.0-only
/*
 * Kernel-based Virtual Machine driver for Linux
 *
 * AMD SVM support
 *
 * Copyright (C) 2006 Qumranet, Inc.
 * Copyright 2010 Red Hat, Inc. and/or its affiliates.
 *
 * Authors:
 *   Yaniv Kamay  <yaniv@qumranet.com>
 *   Avi Kivity   <avi@qumranet.com>
 */

 #ifndef __SVM_SVM_H
 #define __SVM_SVM_H
 
 #include <linux/kvm_types.h>
 #include <linux/kvm_host.h>
 #include <linux/bits.h>
 
 #include <asm/svm.h>
 #include <asm/sev-common.h>
 #include <linux/kvm_host.h>
 
 
 /*
  * The RMP entry format is not architectural. The format is defined in PPR
  * Family 19h Model 01h, Rev B1 processor.
  */
 struct rmpentry {
     union {
         struct {
             u64 assigned	: 1,
                 pagesize	: 1,
                 immutable	: 1,
                 rsvd1	: 9,
                 gpa		: 39,
                 asid	: 10,
                 vmsa	: 1,
                 validated	: 1,
                 rsvd2	: 1;
         };
         u64 lo;
     };
     u64 hi;
 } __packed;
 
 /*
  * Helpers to convert to/from physical addresses for pages whose address is
  * consumed directly by hardware.  Even though it's a physical address, SVM
  * often restricts the address to the natural width, hence 'unsigned long'
  * instead of 'hpa_t'.
  */
 static inline unsigned long __sme_page_pa(struct page *page)
 {
     return __sme_set(page_to_pfn(page) << PAGE_SHIFT);
 }
 
 static inline struct page *__sme_pa_to_page(unsigned long pa)
 {
     return pfn_to_page(__sme_clr(pa) >> PAGE_SHIFT);
 }
 
 #define	IOPM_SIZE PAGE_SIZE * 3
 #define	MSRPM_SIZE PAGE_SIZE * 2
 
 #define MAX_DIRECT_ACCESS_MSRS	48
 #define MSRPM_OFFSETS	32
 extern u32 msrpm_offsets[MSRPM_OFFSETS] __read_mostly;
 extern bool npt_enabled;
 extern int nrips;
 extern int vgif;
 extern bool intercept_smi;
 extern bool x2avic_enabled;
 extern bool vnmi;
 extern int lbrv;
 
 /*
  * Clean bits in VMCB.
  * VMCB_ALL_CLEAN_MASK might also need to
  * be updated if this enum is modified.
  */
 enum {
     VMCB_INTERCEPTS, /* Intercept vectors, TSC offset,
                 pause filter count */
     VMCB_PERM_MAP,   /* IOPM Base and MSRPM Base */
     VMCB_ASID,	 /* ASID */
     VMCB_INTR,	 /* int_ctl, int_vector */
     VMCB_NPT,        /* npt_en, nCR3, gPAT */
     VMCB_CR,	 /* CR0, CR3, CR4, EFER */
     VMCB_DR,         /* DR6, DR7 */
     VMCB_DT,         /* GDT, IDT */
     VMCB_SEG,        /* CS, DS, SS, ES, CPL */
     VMCB_CR2,        /* CR2 only */
     VMCB_LBR,        /* DBGCTL, BR_FROM, BR_TO, LAST_EX_FROM, LAST_EX_TO */
     VMCB_AVIC,       /* AVIC APIC_BAR, AVIC APIC_BACKING_PAGE,
               * AVIC PHYSICAL_TABLE pointer,
               * AVIC LOGICAL_TABLE pointer
               */
     VMCB_SW = 31,    /* Reserved for hypervisor/software use */
 };
 
 #define VMCB_ALL_CLEAN_MASK (					\
     (1U << VMCB_INTERCEPTS) | (1U << VMCB_PERM_MAP) |	\
     (1U << VMCB_ASID) | (1U << VMCB_INTR) |			\
     (1U << VMCB_NPT) | (1U << VMCB_CR) | (1U << VMCB_DR) |	\
     (1U << VMCB_DT) | (1U << VMCB_SEG) | (1U << VMCB_CR2) |	\
     (1U << VMCB_LBR) | (1U << VMCB_AVIC) |			\
     (1U << VMCB_SW))
 
 /* TPR and CR2 are always written before VMRUN */
 #define VMCB_ALWAYS_DIRTY_MASK	((1U << VMCB_INTR) | (1U << VMCB_CR2))
 
 struct kvm_sev_info {
     bool active;		/* SEV enabled guest */
     bool es_active;		/* SEV-ES enabled guest */
     bool need_init;		/* waiting for SEV_INIT2 */
     unsigned int asid;	/* ASID used for this guest */
     unsigned int handle;	/* SEV firmware handle */
     int fd;			/* SEV device fd */
     unsigned long pages_locked; /* Number of pages locked */
     struct list_head regions_list;  /* List of registered regions */
     u64 ap_jump_table;	/* SEV-ES AP Jump Table address */
     u64 vmsa_features;
     u16 ghcb_version;	/* Highest guest GHCB protocol version allowed */
     struct kvm *enc_context_owner; /* Owner of copied encryption context */
     struct list_head mirror_vms; /* List of VMs mirroring */
     struct list_head mirror_entry; /* Use as a list entry of mirrors */
     struct misc_cg *misc_cg; /* For misc cgroup accounting */
     atomic_t migration_in_progress;
     void *snp_context;      /* SNP guest context page */
     void *guest_req_buf;    /* Bounce buffer for SNP Guest Request input */
     void *guest_resp_buf;   /* Bounce buffer for SNP Guest Request output */
     struct mutex guest_req_mutex; /* Must acquire before using bounce buffers */
 };
 
 struct kvm_svm {
     struct kvm kvm;
 
     /* Struct members for AVIC */
     u32 avic_vm_id;
     struct page *avic_logical_id_table_page;
     struct page *avic_physical_id_table_page;
     struct hlist_node hnode;
 
     struct kvm_sev_info sev_info;
 };
 
 struct kvm_vcpu;
 
 struct kvm_vmcb_info {
     struct vmcb *ptr;
     unsigned long pa;
     int cpu;
     uint64_t asid_generation;
 };
 
 struct vmcb_save_area_cached {
     u64 efer;
     u64 cr4;
     u64 cr3;
     u64 cr0;
     u64 dr7;
     u64 dr6;
 };
 
 struct vmcb_ctrl_area_cached {
     u32 intercepts[MAX_INTERCEPT];
     u16 pause_filter_thresh;
     u16 pause_filter_count;
     u64 iopm_base_pa;
     u64 msrpm_base_pa;
     u64 tsc_offset;
     u32 asid;
     u8 tlb_ctl;
     u32 int_ctl;
     u32 int_vector;
     u32 int_state;
     u32 exit_code;
     u32 exit_code_hi;
     u64 exit_info_1;
     u64 exit_info_2;
     u32 exit_int_info;
     u32 exit_int_info_err;
     u64 nested_ctl;
     u32 event_inj;
     u32 event_inj_err;
     u64 next_rip;
     u64 nested_cr3;
     u64 virt_ext;
     u32 clean;
     union {
 #if IS_ENABLED(CONFIG_HYPERV) || IS_ENABLED(CONFIG_KVM_HYPERV)
         struct hv_vmcb_enlightenments hv_enlightenments;
 #endif
         u8 reserved_sw[32];
     };
 };
 
 struct svm_nested_state {
     struct kvm_vmcb_info vmcb02;
     u64 hsave_msr;
     u64 vm_cr_msr;
     u64 vmcb12_gpa;
     u64 last_vmcb12_gpa;
 
     /* These are the merged vectors */
     u32 *msrpm;
 
     /* A VMRUN has started but has not yet been performed, so
      * we cannot inject a nested vmexit yet.  */
     bool nested_run_pending;
 
     /* cache for control fields of the guest */
     struct vmcb_ctrl_area_cached ctl;
 
     /*
      * Note: this struct is not kept up-to-date while L2 runs; it is only
      * valid within nested_svm_vmrun.
      */
     struct vmcb_save_area_cached save;
 
     bool initialized;
 
     /*
      * Indicates whether MSR bitmap for L2 needs to be rebuilt due to
      * changes in MSR bitmap for L1 or switching to a different L2. Note,
      * this flag can only be used reliably in conjunction with a paravirt L1
      * which informs L0 whether any changes to MSR bitmap for L2 were done
      * on its side.
      */
     bool force_msr_bitmap_recalc;
 };
 
 struct vcpu_sev_es_state {
     /* SEV-ES support */
     struct sev_es_save_area *vmsa;
     struct ghcb *ghcb;
     u8 valid_bitmap[16];
     struct kvm_host_map ghcb_map;
     bool received_first_sipi;
     unsigned int ap_reset_hold_type;
 
     /* SEV-ES scratch area support */
     u64 sw_scratch;
     void *ghcb_sa;
     u32 ghcb_sa_len;
     bool ghcb_sa_sync;
     bool ghcb_sa_free;
 
     /* SNP Page-State-Change buffer entries currently being processed */
     u16 psc_idx;
     u16 psc_inflight;
     bool psc_2m;
 
     u64 ghcb_registered_gpa;
 
     struct mutex snp_vmsa_mutex; /* Used to handle concurrent updates of VMSA. */
     gpa_t snp_vmsa_gpa;
     bool snp_ap_waiting_for_reset;
     bool snp_has_guest_vmsa;
 };
 
 struct vcpu_svm {
     struct kvm_vcpu vcpu;
     /* vmcb always points at current_vmcb->ptr, it's purely a shorthand. */
     struct vmcb *vmcb;
     struct kvm_vmcb_info vmcb01;
     struct kvm_vmcb_info *current_vmcb;
     u32 asid;
     u32 sysenter_esp_hi;
     u32 sysenter_eip_hi;
     uint64_t tsc_aux;
 
     u64 msr_decfg;
 
     u64 next_rip;
 
     u64 spec_ctrl;
 
     u64 tsc_ratio_msr;
     /*
      * Contains guest-controlled bits of VIRT_SPEC_CTRL, which will be
      * translated into the appropriate L2_CFG bits on the host to
      * perform speculative control.
      */
     u64 virt_spec_ctrl;
 
     u32 *msrpm;
 
     ulong nmi_iret_rip;
 
     struct svm_nested_state nested;
 
     /* NMI mask value, used when vNMI is not enabled */
     bool nmi_masked;
 
     /*
      * True when NMIs are still masked but guest IRET was just intercepted
      * and KVM is waiting for RIP to change, which will signal that the
      * intercepted IRET was retired and thus NMI can be unmasked.
      */
     bool awaiting_iret_completion;
 
     /*
      * Set when KVM is awaiting IRET completion and needs to inject NMIs as
      * soon as the IRET completes (e.g. NMI is pending injection).  KVM
      * temporarily steals RFLAGS.TF to single-step the guest in this case
      * in order to regain control as soon as the NMI-blocking condition
      * goes away.
      */
     bool nmi_singlestep;
     u64 nmi_singlestep_guest_rflags;
 
     bool nmi_l1_to_l2;
 
     unsigned long soft_int_csbase;
     unsigned long soft_int_old_rip;
     unsigned long soft_int_next_rip;
     bool soft_int_injected;
 
     u32 ldr_reg;
     u32 dfr_reg;
     struct page *avic_backing_page;
     u64 *avic_physical_id_cache;
 
     /*
      * Per-vcpu list of struct amd_svm_iommu_ir:
      * This is used mainly to store interrupt remapping information used
      * when update the vcpu affinity. This avoids the need to scan for
      * IRTE and try to match ga_tag in the IOMMU driver.
      */
     struct list_head ir_list;
     spinlock_t ir_list_lock;
 
     /* Save desired MSR intercept (read: pass-through) state */
     struct {
         DECLARE_BITMAP(read, MAX_DIRECT_ACCESS_MSRS);
         DECLARE_BITMAP(write, MAX_DIRECT_ACCESS_MSRS);
     } shadow_msr_intercept;
 
     struct vcpu_sev_es_state sev_es;
 
     bool guest_state_loaded;
 
     bool x2avic_msrs_intercepted;
 
     /* Guest GIF value, used when vGIF is not enabled */
     bool guest_gif;
 };
 
 
 void recalc_intercepts(struct vcpu_svm *svm);
 
 static __always_inline struct kvm_svm *to_kvm_svm(struct kvm *kvm)
 {
     return container_of(kvm, struct kvm_svm, kvm);
 }
 
 static __always_inline struct kvm_sev_info *to_kvm_sev_info(struct kvm *kvm)
 {
     return &to_kvm_svm(kvm)->sev_info;
 }
 
 
 
 typedef u64 __rcu *tdp_ptep_t;
 
 /*
  * A TDP iterator performs a pre-order walk over a TDP paging structure.
  */
 struct tdp_iter {
     /*
      * The iterator will traverse the paging structure towards the mapping
      * for this GFN.
      */
     gfn_t next_last_level_gfn;
     /*
      * The next_last_level_gfn at the time when the thread last
      * yielded. Only yielding when the next_last_level_gfn !=
      * yielded_gfn helps ensure forward progress.
      */
     gfn_t yielded_gfn;
     /* Pointers to the page tables traversed to reach the current SPTE */
     tdp_ptep_t pt_path[PT64_ROOT_MAX_LEVEL];
     /* A pointer to the current SPTE */
     tdp_ptep_t sptep;
     /* The lowest GFN mapped by the current SPTE */
     gfn_t gfn;
     /* The level of the root page given to the iterator */
     int root_level;
     /* The lowest level the iterator should traverse to */
     int min_level;
     /* The iterator's current level within the paging structure */
     int level;
     /* The address space ID, i.e. SMM vs. regular. */
     int as_id;
     /* A snapshot of the value at sptep */
     u64 old_spte;
     /*
      * Whether the iterator has a valid state. This will be false if the
      * iterator walks off the end of the paging structure.
      */
     bool valid;
     /*
      * True if KVM dropped mmu_lock and yielded in the middle of a walk, in
      * which case tdp_iter_next() needs to restart the walk at the root
      * level instead of advancing to the next entry.
      */
     bool yielded;
 };
 
 
 #endif
 