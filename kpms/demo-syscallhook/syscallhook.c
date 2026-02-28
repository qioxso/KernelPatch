/* SPDX-License-Identifier: GPL-2.0-or-later */
/* * Customized KPM Module for APK Syscall Monitoring (Fixed Version)
 */

#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <uapi/asm-generic/unistd.h>
#include <linux/uaccess.h>
#include <syscall.h>
#include <linux/string.h>
#include <kputils.h>
#include <asm/current.h>
// 注意：移除了 <linux/sched.h>，避免冲突

KPM_NAME("kpm-apk-monitor");
KPM_VERSION("1.0.1");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("Custom");
KPM_DESCRIPTION("KernelPatch Module for APK Syscall Monitoring (openat)");

const char *target_pkg = 0;

// 1. 保留原版的枚举定义
enum pid_type {
    PIDTYPE_PID,
    PIDTYPE_TGID,
    PIDTYPE_PGID,
    PIDTYPE_SID,
    PIDTYPE_MAX,
};

struct pid_namespace;

// 2. 声明我们要动态获取的两个内核函数指针
pid_t (*__task_pid_nr_ns_ptr)(struct task_struct *task, enum pid_type type, struct pid_namespace *ns) = 0;
void (*__get_task_comm_ptr)(char *buf, struct task_struct *tsk) = 0;

void before_openat_monitor(hook_fargs4_t *args, void *udata)
{
    struct task_struct *task = current;
    
    // 1. 移除 ={0}，避免触发 memset，手动将首字符置空
    char comm[16];
    comm[0] = '\0'; 

    if (__get_task_comm_ptr) {
        __get_task_comm_ptr(comm, task);
        comm[15] = '\0'; // 确保安全截断
    }

    if (!target_pkg || strncmp(comm, target_pkg, 15) != 0) {
        return; 
    }

    int dfd = (int)syscall_argn(args, 0);
    const char __user *filename = (typeof(filename))syscall_argn(args, 1);
    int flag = (int)syscall_argn(args, 2);
    umode_t mode = (int)syscall_argn(args, 3);

    // 2. 移除 ={0}，避免触发 memset
    char buf[512];
    buf[0] = '\0'; 
    long copied = compat_strncpy_from_user(buf, filename, sizeof(buf) - 1);

    // 3. 手动确保字符串末尾有结束符 \0
    if (copied > 0 && copied < sizeof(buf)) {
        buf[copied] = '\0'; 
    } else {
        buf[0] = '\0'; // 复制失败时清空
    }

    pid_t pid = -1, tgid = -1;
    if (__task_pid_nr_ns_ptr) {
        pid = __task_pid_nr_ns_ptr(task, PIDTYPE_PID, 0);
        tgid = __task_pid_nr_ns_ptr(task, PIDTYPE_TGID, 0);
    }

    if (copied > 0) {
        pr_info("[KPM-APK-Monitor] Hit! App: %s (PID: %d) openat fd: %d, path: %s, flag: %x\n", 
                comm, pid, dfd, buf, flag);
    } else {
        pr_info("[KPM-APK-Monitor] Hit! App: %s (PID: %d) open invalid pointer.\n", 
                comm, pid);
    }
}

static long apk_monitor_init(const char *args, const char *event, void *__user reserved)
{
    target_pkg = args;
    pr_info("[KPM-APK-Monitor] Init... Target APK: %s\n", target_pkg ? target_pkg : "NONE");

    if (!target_pkg || strlen(target_pkg) == 0) {
        pr_warn("[KPM-APK-Monitor] No target specified!\n");
        return 0;
    }

    // 初始化时动态查找内核函数地址
    __task_pid_nr_ns_ptr = (typeof(__task_pid_nr_ns_ptr))kallsyms_lookup_name("__task_pid_nr_ns");
    __get_task_comm_ptr = (typeof(__get_task_comm_ptr))kallsyms_lookup_name("get_task_comm");

    if (!__get_task_comm_ptr) {
        pr_err("[KPM-APK-Monitor] Error: Cannot find 'get_task_comm' in kernel!\n");
        return -1;
    }

    hook_err_t err = fp_hook_syscalln(__NR_openat, 4, before_openat_monitor, 0, 0);

    if (err) {
        pr_err("[KPM-APK-Monitor] Failed to hook openat! Error: %d\n", err);
    } else {
        pr_info("[KPM-APK-Monitor] Hook successful.\n");
    }

    return 0;
}

static long apk_monitor_control0(const char *args, char *__user out_msg, int outlen)
{
    return 0;
}

static long apk_monitor_exit(void *__user reserved)
{
    pr_info("[KPM-APK-Monitor] Exiting...\n");
    fp_unhook_syscalln(__NR_openat, before_openat_monitor, 0);
    return 0;
}

KPM_INIT(apk_monitor_init);
KPM_CTL0(apk_monitor_control0);
KPM_EXIT(apk_monitor_exit);
