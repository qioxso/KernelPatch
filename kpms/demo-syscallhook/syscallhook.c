/* SPDX-License-Identifier: GPL-2.0-or-later */
/* * Customized KPM Module for APK Syscall Monitoring
 * Based on original syscallhook.c
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
#include <linux/sched.h> // 引入 task_struct 和 current

KPM_NAME("kpm-apk-monitor");
KPM_VERSION("1.0.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("Custom");
KPM_DESCRIPTION("KernelPatch Module for APK Syscall Monitoring (openat)");

// 保存目标 APK 的进程名 (通常是包名的前15个字符)
const char *target_pkg = 0;

// PID 命名空间解析函数指针 (用于在 Android 容器中获取准确的 PID)
enum pid_type {
    PIDTYPE_PID,
    PIDTYPE_TGID,
    PIDTYPE_PGID,
    PIDTYPE_SID,
    PIDTYPE_MAX,
};
struct pid_namespace;
pid_t (*__task_pid_nr_ns_ptr)(struct task_struct *task, enum pid_type type, struct pid_namespace *ns) = 0;

// openat 执行前的拦截函数
void before_openat_monitor(hook_fargs4_t *args, void *udata)
{
    struct task_struct *task = current;

    // 1. 核心过滤逻辑：如果进程名不匹配，直接放行，极大降低系统性能损耗
    // 注意：task->comm 最大长度通常为 15 字符，所以用 strncmp 进行安全比对
    if (!target_pkg || strncmp(task->comm, target_pkg, 15) != 0) {
        return; 
    }

    // 2. 提取 openat 的参数
    int dfd = (int)syscall_argn(args, 0);
    const char __user *filename = (typeof(filename))syscall_argn(args, 1);
    int flag = (int)syscall_argn(args, 2);
    umode_t mode = (int)syscall_argn(args, 3);

    // 3. 安全地将用户态的文件路径拷贝到内核态
    char buf[512] = {0};
    long copied = compat_strncpy_from_user(buf, filename, sizeof(buf) - 1);

    // 4. 获取准确的 PID 和 TGID
    pid_t pid = -1, tgid = -1;
    if (__task_pid_nr_ns_ptr) {
        pid = __task_pid_nr_ns_ptr(task, PIDTYPE_PID, 0);
        tgid = __task_pid_nr_ns_ptr(task, PIDTYPE_TGID, 0);
    } else {
        pid = task->pid;
        tgid = task->tgid;
    }

    // 5. 打印命中目标的日志信息
    if (copied > 0) {
        pr_info("[KPM-APK-Monitor] Hit! App: %s (PID: %d, TGID: %d) openat -> fd: %d, path: %s, flag: %x, mode: %d\n", 
                task->comm, pid, tgid, dfd, buf, flag, mode);
    } else {
        pr_info("[KPM-APK-Monitor] Hit! App: %s (PID: %d) attempted to open invalid pointer.\n", 
                task->comm, pid);
    }
}

// 模块初始化
static long apk_monitor_init(const char *args, const char *event, void *__user reserved)
{
    target_pkg = args;
    pr_info("[KPM-APK-Monitor] Init... Target APK/Process: %s\n", target_pkg ? target_pkg : "NONE");

    if (!target_pkg || strlen(target_pkg) == 0) {
        pr_warn("[KPM-APK-Monitor] No target package specified! Module loaded but doing nothing.\n");
        return 0;
    }

    // 查找并保存 __task_pid_nr_ns 的内核函数地址
    __task_pid_nr_ns_ptr = (typeof(__task_pid_nr_ns_ptr))kallsyms_lookup_name("__task_pid_nr_ns");

    hook_err_t err = HOOK_NO_ERR;

    // 挂载函数指针 Hook 拦截 __NR_openat 系统调用
    err = fp_hook_syscalln(__NR_openat, 4, before_openat_monitor, 0, 0);

    if (err) {
        pr_err("[KPM-APK-Monitor] Failed to hook openat! Error code: %d\n", err);
    } else {
        pr_info("[KPM-APK-Monitor] Successfully hooked openat. Waiting for target process...\n");
    }

    return 0;
}

// 模块控制接口
static long apk_monitor_control0(const char *args, char *__user out_msg, int outlen)
{
    pr_info("[KPM-APK-Monitor] Control received args: %s\n", args);
    return 0;
}

// 模块卸载
static long apk_monitor_exit(void *__user reserved)
{
    pr_info("[KPM-APK-Monitor] Exiting and unhooking...\n");

    // 卸载 Hook，恢复内核原始状态
    fp_unhook_syscalln(__NR_openat, before_openat_monitor, 0);
    
    return 0;
}

KPM_INIT(apk_monitor_init);
KPM_CTL0(apk_monitor_control0);
KPM_EXIT(apk_monitor_exit);
