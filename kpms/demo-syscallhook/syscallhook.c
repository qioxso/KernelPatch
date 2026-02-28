#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <uapi/asm-generic/unistd.h>
#include <linux/uaccess.h>
#include <syscall.h>
#include <kputils.h>
#include <asm/current.h>

KPM_NAME("kpm-stealth-monitor");
KPM_VERSION("4.0.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("Custom");
KPM_DESCRIPTION("Auto-Lock APK Syscall Monitor");

// 全局变量
char g_target_pkg[64];    // 存放你要监控的包名
pid_t g_target_pid = -1;  // 当前锁定的 PID
int g_is_monitoring = 0;  // 监控开关

enum pid_type { PIDTYPE_PID, PIDTYPE_TGID, PIDTYPE_PGID, PIDTYPE_SID, PIDTYPE_MAX };
struct pid_namespace;
pid_t (*__task_pid_nr_ns_ptr)(struct task_struct *task, enum pid_type type, struct pid_namespace *ns) = 0;

// 手写极简 strstr，避免找不到外部符号
char *my_strstr(const char *haystack, const char *needle) {
    if (!haystack || !needle) return 0;
    while (*haystack) {
        const char *h = haystack;
        const char *n = needle;
        while (*haystack && *n && *haystack == *n) {
            haystack++;
            n++;
        }
        if (!*n) return (char *)h;
        haystack = h + 1;
    }
    return 0;
}

// 手写极简 strcpy
void my_strcpy(char *dest, const char *src, int max_len) {
    int i = 0;
    while (src[i] && i < max_len - 1) {
        dest[i] = src[i];
        i++;
    }
    dest[i] = '\0';
}

void before_openat_monitor(hook_fargs4_t *args, void *udata)
{
    if (g_is_monitoring == 0) return;

    struct task_struct *task = current;
    pid_t current_pid = -1;

    if (__task_pid_nr_ns_ptr) {
        current_pid = __task_pid_nr_ns_ptr(task, PIDTYPE_PID, 0);
    }

    int dfd = (int)syscall_argn(args, 0);
    const char __user *filename = (typeof(filename))syscall_argn(args, 1);
    int flag = (int)syscall_argn(args, 2);

    char buf[512];
    buf[0] = '\0';
    long copied = compat_strncpy_from_user(buf, filename, sizeof(buf) - 1);

    if (copied > 0 && copied < sizeof(buf)) {
        buf[copied] = '\0';
    } else {
        buf[0] = '\0';
    }

    // 🔥 核心黑科技：智能锁定 PID
    if (g_target_pid == -1 && copied > 0) {
        // 如果还没锁定目标，且当前被打开的文件路径中包含了我们要监控的包名
        if (my_strstr(buf, g_target_pkg)) {
            g_target_pid = current_pid;
            pr_info("[KPM-Stealth] 🎯 AUTO-LOCKED! Package [%s] launched at PID: %d\n", g_target_pkg, current_pid);
        }
    }

    // 🎯 核心过滤：只拦截锁定的 PID
    if (current_pid != g_target_pid) {
        return;
    }

    if (copied > 0) {
        pr_info("[KPM-Stealth] PID: %d openat -> %s (flag: %x)\n", current_pid, buf, flag);
    }
}

static long monitor_init(const char *args, const char *event, void *__user reserved)
{
    g_target_pkg[0] = '\0';
    g_target_pid = -1;
    g_is_monitoring = 0;

    __task_pid_nr_ns_ptr = (typeof(__task_pid_nr_ns_ptr))kallsyms_lookup_name("__task_pid_nr_ns");

    hook_err_t err = fp_hook_syscalln(__NR_openat, 4, before_openat_monitor, 0, 0);
    if (err) {
        pr_err("[KPM-Stealth] Hook failed: %d\n", err);
    } else {
        pr_info("[KPM-Stealth] Loaded. Waiting for package name via control0...\n");
    }

    return 0;
}

static long monitor_control0(const char *args, char *__user out_msg, int outlen)
{
    if (args && args[0] != '\0') {
        // 收到包名后，重置 PID，进入“埋伏”状态
        my_strcpy(g_target_pkg, args, sizeof(g_target_pkg));
        g_target_pid = -1; 
        g_is_monitoring = 1;
        pr_info("[KPM-Stealth] Sniper mode ON. Waiting for [%s] to launch...\n", g_target_pkg);
    } else {
        g_is_monitoring = 0;
        g_target_pid = -1;
        pr_info("[KPM-Stealth] Monitoring stopped.\n");
    }
    return 0;
}

static long monitor_exit(void *__user reserved)
{
    fp_unhook_syscalln(__NR_openat, before_openat_monitor, 0);
    pr_info("[KPM-Stealth] Exited safely.\n");
    return 0;
}

KPM_INIT(monitor_init);
KPM_CTL0(monitor_control0);
KPM_EXIT(monitor_exit);
