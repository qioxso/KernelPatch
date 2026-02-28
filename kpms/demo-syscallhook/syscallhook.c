#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <uapi/asm-generic/unistd.h>
#include <linux/uaccess.h>
#include <syscall.h>
#include <kputils.h>
#include <asm/current.h>

KPM_NAME("kpm-stealth-monitor");
KPM_VERSION("6.0.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("Custom");
KPM_DESCRIPTION("Ultimate APK Analyzer & Anti-Root-Detect");

char g_target_pkg[64];    
pid_t g_target_pid = -1;  
int g_is_monitoring = 0;  

enum pid_type { PIDTYPE_PID, PIDTYPE_TGID, PIDTYPE_PGID, PIDTYPE_SID, PIDTYPE_MAX };
struct pid_namespace;
pid_t (*__task_pid_nr_ns_ptr)(struct task_struct *task, enum pid_type type, struct pid_namespace *ns) = 0;

// ================== 基础工具函数 ==================
char *my_strstr(const char *haystack, const char *needle) {
    if (!haystack || !needle) return 0;
    while (*haystack) {
        const char *h = haystack;
        const char *n = needle;
        while (*haystack && *n && *haystack == *n) { haystack++; n++; }
        if (!*n) return (char *)h;
        haystack = h + 1;
    }
    return 0;
}

void my_strcpy(char *dest, const char *src, int max_len) {
    int i = 0;
    while (src[i] && i < max_len - 1) { dest[i] = src[i]; i++; }
    dest[i] = '\0';
}

// 获取当前准确 PID
pid_t get_current_pid(void) {
    if (__task_pid_nr_ns_ptr) return __task_pid_nr_ns_ptr(current, PIDTYPE_PID, 0);
    return -1;
}

// 检查是否为锁定的目标 PID
int is_target_pid(void) {
    if (g_is_monitoring == 0 || g_target_pid == -1) return 0;
    return (get_current_pid() == g_target_pid);
}

// ================== 核心提取与自瞄逻辑 ==================
void extract_and_log_path(const char __user *filename, const char *sys_name) {
    if (g_is_monitoring == 0) return;
    pid_t current_pid = get_current_pid();

    char buf[512];
    buf[0] = '\0';
    long copied = compat_strncpy_from_user(buf, filename, sizeof(buf) - 1);
    if (copied > 0 && copied < sizeof(buf)) buf[copied] = '\0'; else buf[0] = '\0';

    // 智能锁定逻辑
    if (g_target_pid == -1 && copied > 0 && g_target_pkg[0] != '\0') {
        if (my_strstr(buf, g_target_pkg)) {
            g_target_pid = current_pid;
            pr_info("[KPM-Stealth] 🎯 AUTO-LOCKED! Package [%s] locked at PID: %d\n", g_target_pkg, current_pid);
        }
    }

    if (current_pid != g_target_pid) return;

    if (copied > 0) pr_info("[KPM-Stealth] PID: %d [%s] -> %s\n", current_pid, sys_name, buf);
}

// ================== 执行前 Hook (信息获取) ==================

void before_openat(hook_fargs4_t *args, void *udata) {
    extract_and_log_path((const char __user *)syscall_argn(args, 1), "openat");
}
void before_faccessat(hook_fargs4_t *args, void *udata) {
    extract_and_log_path((const char __user *)syscall_argn(args, 1), "faccessat");
}
void before_execve(hook_fargs4_t *args, void *udata) {
    extract_and_log_path((const char __user *)syscall_argn(args, 0), "execve");
}
void before_unlinkat(hook_fargs4_t *args, void *udata) {
    extract_and_log_path((const char __user *)syscall_argn(args, 1), "unlinkat (DELETE)");
}
void before_mkdirat(hook_fargs4_t *args, void *udata) {
    extract_and_log_path((const char __user *)syscall_argn(args, 1), "mkdirat");
}

// 专门处理 ptrace (它没有路径参数)
void before_ptrace(hook_fargs4_t *args, void *udata) {
    if (!is_target_pid()) return;
    long request = (long)syscall_argn(args, 0);
    long pid = (long)syscall_argn(args, 1);
    pr_info("[KPM-Stealth] PID: %d [ptrace] -> request: %ld, target_pid: %ld\n", g_target_pid, request, pid);
}


// ================== 执行后 Hook (主动篡改 / Root 隐藏) ==================

void active_defense_after_hook(hook_fargs4_t *args, int path_arg_index) {
    if (!is_target_pid()) return;

    const char __user *filename = (const char __user *)syscall_argn(args, path_arg_index);
    char buf[256]; buf[0] = '\0';
    long copied = compat_strncpy_from_user(buf, filename, sizeof(buf) - 1);
    if (copied > 0 && copied < sizeof(buf)) buf[copied] = '\0';

    // 如果 App 试图寻找这些敏感特征，直接返回 -2 (-ENOENT 文件不存在)
    if (my_strstr(buf, "su") || my_strstr(buf, "magisk") || my_strstr(buf, "xposed") || my_strstr(buf, "lsposed")) {
        pr_info("[KPM-Stealth] 🛡️ BLOCKED Root/Hook Detection: %s\n", buf);
        args->ret = -2; // 强行篡改返回值
    }
}

void after_openat(hook_fargs4_t *args, void *udata) { active_defense_after_hook(args, 1); }
void after_faccessat(hook_fargs4_t *args, void *udata) { active_defense_after_hook(args, 1); }


// ================== 生命周期管理 ==================

static long monitor_init(const char *args, const char *event, void *__user reserved) {
    g_target_pkg[0] = '\0'; g_target_pid = -1; g_is_monitoring = 0;
    __task_pid_nr_ns_ptr = (typeof(__task_pid_nr_ns_ptr))kallsyms_lookup_name("__task_pid_nr_ns");

    // 挂载执行前 Hook (获取信息)
    fp_hook_syscalln(__NR_execve, 3, before_execve, 0, 0);
    fp_hook_syscalln(__NR_unlinkat, 3, before_unlinkat, 0, 0);
    fp_hook_syscalln(__NR_mkdirat, 3, before_mkdirat, 0, 0);
    fp_hook_syscalln(__NR_ptrace, 4, before_ptrace, 0, 0);

    // 挂载执行前与执行后 Hook (获取信息 + 篡改返回值)
    fp_hook_syscalln(__NR_openat, 4, before_openat, after_openat, 0);
    fp_hook_syscalln(__NR_faccessat, 4, before_faccessat, after_faccessat, 0);
    
    pr_info("[KPM-Stealth] V6 Ultimate Loaded.\n");
    return 0;
}

static long monitor_control0(const char *args, char *__user out_msg, int outlen) {
    if (args && args[0] != '\0') {
        my_strcpy(g_target_pkg, args, sizeof(g_target_pkg));
        g_target_pid = -1; g_is_monitoring = 1;
        pr_info("[KPM-Stealth] Sniper mode ON. Waiting for [%s]...\n", g_target_pkg);
    } else {
        g_is_monitoring = 0; g_target_pid = -1;
        pr_info("[KPM-Stealth] Monitoring stopped.\n");
    }
    return 0;
}

static long monitor_exit(void *__user reserved) {
    fp_unhook_syscalln(__NR_execve, before_execve, 0);
    fp_unhook_syscalln(__NR_unlinkat, before_unlinkat, 0);
    fp_unhook_syscalln(__NR_mkdirat, before_mkdirat, 0);
    fp_unhook_syscalln(__NR_ptrace, before_ptrace, 0);
    fp_unhook_syscalln(__NR_openat, before_openat, after_openat);
    fp_unhook_syscalln(__NR_faccessat, before_faccessat, after_faccessat);
    pr_info("[KPM-Stealth] Exited safely.\n");
    return 0;
}

KPM_INIT(monitor_init);
KPM_CTL0(monitor_control0);
KPM_EXIT(monitor_exit);
