#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <uapi/asm-generic/unistd.h>
#include <linux/uaccess.h>
#include <syscall.h>
#include <kputils.h>
#include <asm/current.h>

KPM_NAME("kpm-stealth-monitor");
KPM_VERSION("8.0.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("Custom");
KPM_DESCRIPTION("V8 Deep-Net Analyzer (TGID, kill, rename)");

char g_target_pkg[64];    
pid_t g_target_tgid = -1; // 🔥 升级为 TGID (线程组ID)，捕获所有子线程！
int g_is_monitoring = 0;  

enum pid_type { PIDTYPE_PID, PIDTYPE_TGID, PIDTYPE_PGID, PIDTYPE_SID, PIDTYPE_MAX };
struct pid_namespace;
pid_t (*__task_pid_nr_ns_ptr)(struct task_struct *task, enum pid_type type, struct pid_namespace *ns) = 0;
unsigned long (*__my_copy_from_user)(void *to, const void __user *from, unsigned long n) = 0;

struct custom_sockaddr_in {
    unsigned short sin_family;
    unsigned short sin_port;
    unsigned int   sin_addr;
    unsigned char  __pad[8];
};

// ================== 基础工具 ==================
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

// 🔥 获取当前线程组 ID (App主进程的PID，所有子线程共享)
pid_t get_current_tgid(void) {
    if (__task_pid_nr_ns_ptr) return __task_pid_nr_ns_ptr(current, PIDTYPE_TGID, 0);
    return -1;
}

pid_t get_current_tid(void) {
    if (__task_pid_nr_ns_ptr) return __task_pid_nr_ns_ptr(current, PIDTYPE_PID, 0);
    return -1;
}

int is_target_tgid(void) {
    if (g_is_monitoring == 0 || g_target_tgid == -1) return 0;
    return (get_current_tgid() == g_target_tgid);
}

// ================== 智能锁定与路径提取 ==================
void extract_and_log_path(const char __user *filename, const char *sys_name) {
    if (g_is_monitoring == 0) return;
    pid_t current_tgid = get_current_tgid();
    pid_t current_tid = get_current_tid();

    char buf[512]; buf[0] = '\0';
    long copied = compat_strncpy_from_user(buf, filename, sizeof(buf) - 1);
    if (copied > 0 && copied < sizeof(buf)) buf[copied] = '\0'; else buf[0] = '\0';

    // 智能锁定逻辑 (按 TGID 锁定整个 App 家族)
    if (g_target_tgid == -1 && copied > 0 && g_target_pkg[0] != '\0') {
        if (my_strstr(buf, g_target_pkg)) {
            g_target_tgid = current_tgid;
            pr_info("[KPM-V8] 🎯 AUTO-LOCKED! Package [%s] locked at TGID: %d\n", g_target_pkg, current_tgid);
        }
    }

    if (current_tgid != g_target_tgid) return;
    if (copied > 0) pr_info("[KPM-V8] TID: %d [%s] -> %s\n", current_tid, sys_name, buf);
}

// ================== 核心拦截区 (扩展版) ==================

void before_openat(hook_fargs4_t *args, void *udata) { extract_and_log_path((const char __user *)syscall_argn(args, 1), "openat"); }
void before_faccessat(hook_fargs4_t *args, void *udata) { extract_and_log_path((const char __user *)syscall_argn(args, 1), "faccessat"); }
void before_execve(hook_fargs4_t *args, void *udata) { extract_and_log_path((const char __user *)syscall_argn(args, 0), "execve"); }
void before_unlinkat(hook_fargs4_t *args, void *udata) { extract_and_log_path((const char __user *)syscall_argn(args, 1), "unlinkat"); }

// 📦 载荷转移监控 (renameat)
void before_renameat(hook_fargs4_t *args, void *udata) {
    if (!is_target_tgid()) return;
    pid_t tid = get_current_tid();
    
    char old_buf[256]; old_buf[0] = '\0';
    char new_buf[256]; new_buf[0] = '\0';
    
    long c1 = compat_strncpy_from_user(old_buf, (const char __user *)syscall_argn(args, 1), sizeof(old_buf) - 1);
    long c2 = compat_strncpy_from_user(new_buf, (const char __user *)syscall_argn(args, 3), sizeof(new_buf) - 1);
    
    if (c1 > 0 && c1 < sizeof(old_buf)) old_buf[c1] = '\0';
    if (c2 > 0 && c2 < sizeof(new_buf)) new_buf[c2] = '\0';
    
    pr_info("[KPM-V8] 📦 RENAME! TID: %d [renameat] -> From: %s, To: %s\n", tid, old_buf, new_buf);
}

// 🗡️ 进程猎杀/自杀监控 (kill)
void before_kill(hook_fargs4_t *args, void *udata) {
    if (!is_target_tgid()) return;
    pid_t target_pid = (pid_t)syscall_argn(args, 0);
    int sig = (int)syscall_argn(args, 1);
    
    // sig 0 通常是用来探测进程是否存活，9 是强杀
    pr_info("[KPM-V8] 🗡️ KILL SIGNAL! TID: %d [kill] -> Target PID: %d, Signal: %d\n", get_current_tid(), target_pid, sig);
}

// 🌐 网络连接监控
void before_connect(hook_fargs4_t *args, void *udata) {
    if (!is_target_tgid()) return;
    const void __user *uservaddr = (const void __user *)syscall_argn(args, 1);
    struct custom_sockaddr_in addr;
    if (__my_copy_from_user && __my_copy_from_user(&addr, uservaddr, sizeof(struct custom_sockaddr_in)) == 0) {
        if (addr.sin_family == 2) { 
            unsigned short port = ((addr.sin_port & 0xFF) << 8) | ((addr.sin_port & 0xFF00) >> 8);
            unsigned char *ip = (unsigned char *)&addr.sin_addr;
            pr_info("[KPM-V8] 🌐 NET! TID: %d [connect] -> IP: %d.%d.%d.%d, Port: %d\n", 
                    get_current_tid(), ip[0], ip[1], ip[2], ip[3], port);
        }
    }
}

void before_mprotect(hook_fargs4_t *args, void *udata) {
    if (!is_target_tgid()) return;
    unsigned long start = (unsigned long)syscall_argn(args, 0);
    unsigned long len = (unsigned long)syscall_argn(args, 1);
    unsigned long prot = (unsigned long)syscall_argn(args, 2);
    if (prot & 4) {
        pr_info("[KPM-V8] 🧠 EXEC MEM! TID: %d [mprotect] -> Addr: %lx, Size: %lu, Prot: %lx\n", 
                get_current_tid(), start, len, prot);
    }
}

void before_prctl(hook_fargs4_t *args, void *udata) {
    if (!is_target_tgid()) return;
    long option = (long)syscall_argn(args, 0);
    if (option == 4) pr_info("[KPM-V8] 🛑 ANTI-DUMP! TID: %d [prctl(PR_SET_DUMPABLE)]\n", get_current_tid());
}

// 🛡️ 主动防御区
void active_defense_after_hook(hook_fargs4_t *args, int path_arg_index) {
    if (!is_target_tgid()) return;
    const char __user *filename = (const char __user *)syscall_argn(args, path_arg_index);
    char buf[256]; buf[0] = '\0';
    long copied = compat_strncpy_from_user(buf, filename, sizeof(buf) - 1);
    if (copied > 0 && copied < sizeof(buf)) buf[copied] = '\0';

    if (my_strstr(buf, "su") || my_strstr(buf, "magisk") || my_strstr(buf, "xposed") || my_strstr(buf, "frida")) {
        pr_info("[KPM-V8] 🛡️ BLOCKED DETECT: %s\n", buf);
        args->ret = -2; // 篡改返回值，伪装文件不存在
    }
}

void after_openat(hook_fargs4_t *args, void *udata) { active_defense_after_hook(args, 1); }
void after_faccessat(hook_fargs4_t *args, void *udata) { active_defense_after_hook(args, 1); }

// ================== 生命周期 ==================

static long monitor_init(const char *args, const char *event, void *__user reserved) {
    g_target_pkg[0] = '\0'; g_target_tgid = -1; g_is_monitoring = 0;
    __task_pid_nr_ns_ptr = (typeof(__task_pid_nr_ns_ptr))kallsyms_lookup_name("__task_pid_nr_ns");
    __my_copy_from_user = (void *)kallsyms_lookup_name("_copy_from_user");
    if (!__my_copy_from_user) __my_copy_from_user = (void *)kallsyms_lookup_name("__arch_copy_from_user");

    // 批量挂载 Hook
    fp_hook_syscalln(__NR_execve, 3, before_execve, 0, 0);
    fp_hook_syscalln(__NR_unlinkat, 3, before_unlinkat, 0, 0);
    fp_hook_syscalln(__NR_connect, 3, before_connect, 0, 0);
    fp_hook_syscalln(__NR_mprotect, 3, before_mprotect, 0, 0);
    fp_hook_syscalln(__NR_prctl, 5, before_prctl, 0, 0);
    fp_hook_syscalln(__NR_renameat, 4, before_renameat, 0, 0);
    fp_hook_syscalln(__NR_kill, 2, before_kill, 0, 0);

    fp_hook_syscalln(__NR_openat, 4, before_openat, after_openat, 0);
    fp_hook_syscalln(__NR_faccessat, 4, before_faccessat, after_faccessat, 0);
    
    pr_info("[KPM-V8] Loaded! Watching All Threads, Network, Files, Memory, Signals.\n");
    return 0;
}

static long monitor_control0(const char *args, char *__user out_msg, int outlen) {
    if (args && args[0] != '\0') {
        my_strcpy(g_target_pkg, args, sizeof(g_target_pkg));
        g_target_tgid = -1; g_is_monitoring = 1;
        pr_info("[KPM-V8] Sniper ON. Target: [%s]...\n", g_target_pkg);
    } else {
        g_is_monitoring = 0; g_target_tgid = -1;
        pr_info("[KPM-V8] Stopped.\n");
    }
    return 0;
}

static long monitor_exit(void *__user reserved) {
    // 批量卸载 Hook
    fp_unhook_syscalln(__NR_execve, before_execve, 0);
    fp_unhook_syscalln(__NR_unlinkat, before_unlinkat, 0);
    fp_unhook_syscalln(__NR_connect, before_connect, 0);
    fp_unhook_syscalln(__NR_mprotect, before_mprotect, 0);
    fp_unhook_syscalln(__NR_prctl, before_prctl, 0);
    fp_unhook_syscalln(__NR_renameat, before_renameat, 0);
    fp_unhook_syscalln(__NR_kill, before_kill, 0);
    
    fp_unhook_syscalln(__NR_openat, before_openat, after_openat);
    fp_unhook_syscalln(__NR_faccessat, before_faccessat, after_faccessat);
    pr_info("[KPM-V8] Exited.\n");
    return 0;
}

KPM_INIT(monitor_init);
KPM_CTL0(monitor_control0);
KPM_EXIT(monitor_exit);
