/* SPDX-License-Identifier: GPL-2.0-or-later */

#include <compiler.h>
#include <kpmodule.h>
#include <hook.h>
#include <kallsyms.h>
#include <syscall.h>
#include <kputils.h>
#include <ksyms.h>

#include <linux/printk.h>
#include <linux/kernel.h>
#include <linux/mm_types.h>
#include <linux/string.h>
#include <linux/uaccess.h>

#include <asm-generic/unistd.h>
#include <common.h>
#include <ktypes.h>

KPM_NAME("amem-kpm");
KPM_VERSION("1.0.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("OpenAI");
KPM_DESCRIPTION("AMem process_vm hook bridge for Android process memory read/write");

#ifndef __NR_process_vm_readv
#define __NR_process_vm_readv 270
#endif

#ifndef __NR_process_vm_writev
#define __NR_process_vm_writev 271
#endif

#define AMEM_PAGE_MIN(a, b) ((a) < (b) ? (a) : (b))

struct iovec {
    void __user *iov_base;
    __kernel_size_t iov_len;
};

#define UIO_MAXIOV 1024

int kfunc_def(sprintf)(char *buf, const char *fmt, ...);
struct task_struct *kfunc_def(find_task_by_vpid)(pid_t pid);
struct mm_struct *kfunc_def(get_task_mm)(struct task_struct *task);
void kfunc_def(mmput)(struct mm_struct *mm);
void *kfunc_def(vmalloc)(unsigned long size);
void *kfunc_def(vmalloc_noprof)(unsigned long size);
void kfunc_def(vfree)(const void *addr);
unsigned long kfunc_def(__arch_copy_to_user)(void __user *to, const void *from, unsigned long n);
unsigned long kfunc_def(__arch_copy_from_user)(void *to, const void __user *from, unsigned long n);

u64 kvar_def(memstart_addr);

static int read_hook_installed = 0;
static int write_hook_installed = 0;
static uint64_t read_count = 0;
static uint64_t write_count = 0;

static uint64_t phys_offset = 0;
static uint64_t page_offset = 0;
static uint64_t page_shift_ = 12;
static uint64_t page_level_ = 4;
static uint64_t page_size_ = 4096;

static inline uint64_t phys_to_virt_(uint64_t phys)
{
    return ((unsigned long)(phys - phys_offset) | page_offset);
}

static inline uint64_t virt_to_phys_(uint64_t virt)
{
    if (kver > VERSION(5, 0, 0)) {
        return (virt - page_offset) + phys_offset;
    }
    return ((virt & ~page_offset) + phys_offset);
}

static uint64_t pgtable_to_tkpa(uint64_t pgd, uint64_t va)
{
    uint64_t pxd_bits = page_shift_ - 3;
    uint64_t pxd_ptrs = 1u << pxd_bits;
    uint64_t pxd_va = pgd;
    uint64_t pxd_pa = virt_to_phys_(pxd_va);
    uint64_t block_lv = 0;

    for (int64_t lv = 4 - page_level_; lv < 4; lv++) {
        uint64_t pxd_shift = (page_shift_ - 3) * (4 - lv) + 3;
        uint64_t pxd_index = (va >> pxd_shift) & (pxd_ptrs - 1);
        uint64_t pxd_entry_va = pxd_va + pxd_index * 8;
        uint64_t pxd_desc = *((uint64_t *)pxd_entry_va);

        if ((pxd_desc & 0x3) == 0x3) {
            pxd_pa = pxd_desc & (((1ul << (48 - page_shift_)) - 1) << page_shift_);
        } else if ((pxd_desc & 0x3) == 0x1) {
            uint64_t block_bits = (3 - lv) * pxd_bits + page_shift_;
            pxd_pa = pxd_desc & (((1ul << (48 - block_bits)) - 1) << block_bits);
            block_lv = lv;
        } else {
            return 0;
        }

        pxd_va = phys_to_virt_(pxd_pa);
        if (block_lv) {
            break;
        }
    }

    {
        uint64_t left_bit = page_shift_ + (block_lv ? (3 - block_lv) * pxd_bits : 0);
        return pxd_pa + (va & ((1u << left_bit) - 1));
    }
}

static int pgtable_init(void)
{
    uint64_t tcr_el1 = 0;
    uint64_t t1sz = 0;
    uint64_t va_bits = 0;
    uint64_t tg1 = 0;

    asm volatile("mrs %0, tcr_el1" : "=r"(tcr_el1));
    t1sz = (tcr_el1 << 42) >> 58;
    va_bits = 64 - t1sz;
    tg1 = (tcr_el1 << 32) >> 62;

    page_shift_ = 12;
    if (tg1 == 1) {
        page_shift_ = 14;
    } else if (tg1 == 3) {
        page_shift_ = 16;
    }

    page_level_ = (va_bits - 4) / (page_shift_ - 3);

    if (kver > VERSION(5, 0, 0)) {
        page_offset = (-(UL(1) << va_bits));
    } else {
        page_offset = (UL(0xffffffffffffffff) - (UL(1) << (va_bits - 1)) + 1);
    }

    kvar_match(memstart_addr, NULL, 0);
    phys_offset = *kv_memstart_addr;
    page_size_ = 1ul << page_shift_;
    return 0;
}

static int copy_user_iovec(struct iovec **out_iov,
                           const struct iovec __user *user_iov,
                           unsigned long iovcnt)
{
    size_t bytes = 0;
    struct iovec *iov = NULL;

    if (!out_iov || !user_iov || iovcnt == 0 || iovcnt > UIO_MAXIOV) {
        return -EINVAL;
    }

    bytes = iovcnt * sizeof(struct iovec);
    if (kf_vmalloc) {
        iov = kf_vmalloc(bytes);
    } else if (kf_vmalloc_noprof) {
        iov = kf_vmalloc_noprof(bytes);
    }
    if (!iov) {
        return -ENOMEM;
    }

    if (kf___arch_copy_from_user(iov, user_iov, bytes) != 0) {
        if (kf_vfree) {
            kf_vfree(iov);
        }
        return -EFAULT;
    }

    *out_iov = iov;
    return 0;
}

static void free_user_iovec(struct iovec *iov)
{
    if (iov) {
        if (kf_vfree) {
            kf_vfree(iov);
        }
    }
}

static int copy_process_bytes(pid_t pid, uint64_t remote_addr,
                              void __user *local_buf, size_t len, int write)
{
    struct task_struct *task = NULL;
    struct mm_struct *mm = NULL;
    uintptr_t pgd = 0;
    size_t copied = 0;

    task = kf_find_task_by_vpid(pid);
    if (!task) {
        return -ESRCH;
    }

    mm = kf_get_task_mm(task);
    if (!mm) {
        return -EINVAL;
    }

    pgd = *(uintptr_t *)((uintptr_t)mm + mm_struct_offset.pgd_offset);

    while (copied < len) {
        uint64_t va = remote_addr + copied;
        uint64_t pa = pgtable_to_tkpa(pgd, va);
        uint64_t page_off = va & (page_size_ - 1);
        size_t chunk = AMEM_PAGE_MIN(len - copied, page_size_ - page_off);
        void *kva = NULL;
        unsigned long left = 0;

        if (!pa) {
            kf_mmput(mm);
            return -EFAULT;
        }

        kva = (void *)phys_to_virt_(pa);
        if (!write) {
            left = kf___arch_copy_to_user((void __user *)((uintptr_t)local_buf + copied), kva, chunk);
        } else {
            left = kf___arch_copy_from_user(kva, (const void __user *)((uintptr_t)local_buf + copied), chunk);
        }

        if (left != 0) {
            kf_mmput(mm);
            return -EFAULT;
        }

        copied += chunk;
    }

    kf_mmput(mm);
    return 0;
}

static ssize_t do_process_vm_rw(pid_t pid,
                                const struct iovec __user *local_iov,
                                unsigned long liovcnt,
                                const struct iovec __user *remote_iov,
                                unsigned long riovcnt,
                                unsigned long flags,
                                int write)
{
    struct iovec *local = NULL;
    struct iovec *remote = NULL;
    ssize_t total = 0;
    unsigned long i = 0;
    unsigned long j = 0;
    int rc = 0;

    (void)flags;

    if (!kf_find_task_by_vpid || !kf_get_task_mm || !kf_mmput ||
        !kf___arch_copy_to_user || !kf___arch_copy_from_user) {
        return -ENOSYS;
    }

    if (!kf_find_task_by_vpid(pid)) {
        return -ESRCH;
    }

    rc = copy_user_iovec(&local, local_iov, liovcnt);
    if (rc < 0) {
        return rc;
    }

    rc = copy_user_iovec(&remote, remote_iov, riovcnt);
    if (rc < 0) {
        free_user_iovec(local);
        return rc;
    }

    while (i < liovcnt && j < riovcnt) {
        size_t local_len = local[i].iov_len;
        size_t remote_len = remote[j].iov_len;
        size_t chunk = AMEM_PAGE_MIN(local_len, remote_len);

        if (chunk > 0) {
            rc = copy_process_bytes(pid,
                                    (uint64_t)(uintptr_t)remote[j].iov_base,
                                    local[i].iov_base,
                                    chunk,
                                    write);
            if (rc < 0) {
                if (total == 0) {
                    total = rc;
                }
                break;
            }

            total += chunk;
            local[i].iov_base = (void __user *)((uintptr_t)local[i].iov_base + chunk);
            local[i].iov_len -= chunk;
            remote[j].iov_base = (void __user *)((uintptr_t)remote[j].iov_base + chunk);
            remote[j].iov_len -= chunk;
        }

        if (local[i].iov_len == 0) {
            i++;
        }
        if (remote[j].iov_len == 0) {
            j++;
        }
    }

    free_user_iovec(local);
    free_user_iovec(remote);

    if (write) {
        write_count++;
    } else {
        read_count++;
    }
    return total;
}

static void before_process_vm_readv(hook_fargs6_t *args, void *udata)
{
    pid_t pid = (pid_t)syscall_argn(args, 0);
    const struct iovec __user *local_iov = (typeof(local_iov))syscall_argn(args, 1);
    unsigned long liovcnt = (unsigned long)syscall_argn(args, 2);
    const struct iovec __user *remote_iov = (typeof(remote_iov))syscall_argn(args, 3);
    unsigned long riovcnt = (unsigned long)syscall_argn(args, 4);
    unsigned long flags = (unsigned long)syscall_argn(args, 5);

    (void)udata;
    args->ret = do_process_vm_rw(pid, local_iov, liovcnt, remote_iov, riovcnt, flags, 0);
    args->skip_origin = 1;
}

static void before_process_vm_writev(hook_fargs6_t *args, void *udata)
{
    pid_t pid = (pid_t)syscall_argn(args, 0);
    const struct iovec __user *local_iov = (typeof(local_iov))syscall_argn(args, 1);
    unsigned long liovcnt = (unsigned long)syscall_argn(args, 2);
    const struct iovec __user *remote_iov = (typeof(remote_iov))syscall_argn(args, 3);
    unsigned long riovcnt = (unsigned long)syscall_argn(args, 4);
    unsigned long flags = (unsigned long)syscall_argn(args, 5);

    (void)udata;
    args->ret = do_process_vm_rw(pid, local_iov, liovcnt, remote_iov, riovcnt, flags, 1);
    args->skip_origin = 1;
}

static int write_text_response(char *__user out_msg, int outlen, const char *buf)
{
    int len = 0;

    if (!out_msg || outlen <= 0 || !buf) {
        return -EINVAL;
    }

    len = strlen(buf);
    if (len >= outlen) {
        len = outlen - 1;
    }

    if (len < 0) {
        return -EINVAL;
    }

    if (compat_copy_to_user(out_msg, buf, len) != 0) {
        return -EFAULT;
    }

    {
        char zero = '\0';
        if (compat_copy_to_user(out_msg + len, &zero, 1) != 0) {
            return -EFAULT;
        }
    }
    return 0;
}

static long amem_kpm_init(const char *args, const char *event, void *__user reserved)
{
    hook_err_t err = 0;

    (void)args;
    (void)reserved;

    pr_info("amem-kpm init: event=%s\n", event ? event : "(null)");

    pgtable_init();
    kfunc_match(sprintf, NULL, 0);
    kfunc_match(find_task_by_vpid, NULL, 0);
    kfunc_match(get_task_mm, NULL, 0);
    kfunc_match(mmput, NULL, 0);
    kfunc_match(vmalloc, NULL, 0);
    kfunc_match(vmalloc_noprof, NULL, 0);
    kfunc_match(vfree, NULL, 0);
    kfunc_match(__arch_copy_to_user, NULL, 0);
    kfunc_match(__arch_copy_from_user, NULL, 0);

    if (!kf_find_task_by_vpid || !kf_get_task_mm || !kf_mmput ||
        !kf___arch_copy_to_user || !kf___arch_copy_from_user) {
        pr_err("amem-kpm: missing required kernel symbols\n");
        return -ENOSYS;
    }
    if (!kf_vfree || (!kf_vmalloc && !kf_vmalloc_noprof)) {
        pr_err("amem-kpm: missing vmalloc/vfree symbols\n");
        return -ENOSYS;
    }

    err = inline_hook_syscalln(__NR_process_vm_readv, 6, before_process_vm_readv, NULL, NULL);
    if (!err) {
        read_hook_installed = 1;
    } else {
        pr_err("amem-kpm: hook process_vm_readv failed: %d\n", err);
    }

    err = inline_hook_syscalln(__NR_process_vm_writev, 6, before_process_vm_writev, NULL, NULL);
    if (!err) {
        write_hook_installed = 1;
    } else {
        pr_err("amem-kpm: hook process_vm_writev failed: %d\n", err);
    }

    if (!read_hook_installed && !write_hook_installed) {
        return -EINVAL;
    }

    return 0;
}

static long amem_kpm_control0(const char *args, char *__user out_msg, int outlen)
{
    char buf[1024];
    unsigned long sym = 0;

    if (!args || !strcmp(args, "status")) {
        sprintf(buf,
                "name=amem-kpm\n"
                "read_hook=%d\n"
                "write_hook=%d\n"
                "read_count=%llu\n"
                "write_count=%llu\n"
                "kernel=%x\n"
                "kp=%x\n",
                read_hook_installed,
                write_hook_installed,
                (unsigned long long)read_count,
                (unsigned long long)write_count,
                kver,
                kpver);
        return write_text_response(out_msg, outlen, buf);
    }

    if (!strcmp(args, "reset")) {
        read_count = 0;
        write_count = 0;
        return write_text_response(out_msg, outlen, "ok");
    }

    if (!strcmp(args, "caps")) {
        sprintf(buf,
                "register_user_hw_breakpoint=%lx\n"
                "modify_user_hw_breakpoint=%lx\n"
                "unregister_hw_breakpoint=%lx\n"
                "user_enable_single_step=%lx\n"
                "user_disable_single_step=%lx\n"
                "ptrace_hbptriggered=%lx\n"
                "arch_ptrace=%lx\n",
                kallsyms_lookup_name("register_user_hw_breakpoint"),
                kallsyms_lookup_name("modify_user_hw_breakpoint"),
                kallsyms_lookup_name("unregister_hw_breakpoint"),
                kallsyms_lookup_name("user_enable_single_step"),
                kallsyms_lookup_name("user_disable_single_step"),
                kallsyms_lookup_name("ptrace_hbptriggered"),
                kallsyms_lookup_name("arch_ptrace"));
        return write_text_response(out_msg, outlen, buf);
    }

    if (!strncmp(args, "sym:", 4)) {
        sym = kallsyms_lookup_name(args + 4);
        sprintf(buf, "%lx", sym);
        return write_text_response(out_msg, outlen, buf);
    }

    return write_text_response(out_msg, outlen,
                               "commands: status | reset | caps | sym:<symbol>");
}

static long amem_kpm_exit(void *__user reserved)
{
    (void)reserved;

    if (read_hook_installed) {
        inline_unhook_syscalln(__NR_process_vm_readv, before_process_vm_readv, NULL);
        read_hook_installed = 0;
    }
    if (write_hook_installed) {
        inline_unhook_syscalln(__NR_process_vm_writev, before_process_vm_writev, NULL);
        write_hook_installed = 0;
    }

    pr_info("amem-kpm exit\n");
    return 0;
}

KPM_INIT(amem_kpm_init);
KPM_CTL0(amem_kpm_control0);
KPM_EXIT(amem_kpm_exit);
