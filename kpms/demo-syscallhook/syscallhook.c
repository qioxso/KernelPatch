#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <uapi/asm-generic/unistd.h>
#include <linux/uaccess.h>
#include <syscall.h>
#include <kputils.h>
#include <asm/current.h>

KPM_NAME("kpm-stealth-monitor");
KPM_VERSION("7.1.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("Custom");
KPM_DESCRIPTION("God Mode APK Analyzer (Fixed Net Hook)");

char g_target_pkg[64];    
pid_t g_target_pid = -1;  
int g_is_monitoring = 0;  

enum pid_type { PIDTYPE_PID, PIDTYPE_TGID, PIDTYPE_PGID, PIDTYPE_SID, PIDTYPE_MAX };
struct pid_namespace;
pid_t (*__task_pid_nr_ns_ptr)(struct task_struct *task, enum pid_type type, struct pid_namespace *ns) = 0;

// 动态获取内存拷贝函数的指针
unsigned long (*__my_copy_from_user)(void *to, const void __user *from, unsigned long n) = 0;

struct custom_sockaddr_in {
    unsigned short sin_family;
    unsigned short sin_port;
    unsigned int   sin_addr;
    unsigned char  __pad[8];
};

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

pid_t get_current_pid(void) {
    if (__task_pid_nr_ns_ptr) return __task_pid_nr_ns_ptr(current, PIDTYPE_PID, 0);
    return -1;
}

int is_target_pid(void) {
    if (g_is_monitoring == 0 || g_target_pid == -1) return 0;
    return (get_current_pid() == g_target_pid);
}

// ================== 智能锁定与路径提取 ==================
void extract_and_log_path(const char __user *filename, const char *sys_name) {
    if (g_is_monitoring == 0) return;
    pid_t current_pid = get_current_pid();

    char buf[512];
    buf[0] = '\0';
    long copied = compat_strncpy_from_user(buf, filename, sizeof(buf) - 1);
    if (copied > 0 && copied < sizeof(buf)) buf[copied] = '\0'; else buf[0] = '\0';

    if (g_target_pid == -1 && copied > 0 && g_target_pkg[0] != '\0') {
        if (my_strstr(buf, g_target_pkg)) {
            g_target_pid = current_pid;
            pr_info("[KPM-GodMode] 🎯 AUTO-LOCKED! Package [%s] locked at PID: %d\n", g_target_pkg, current_pid);
        }
    }

    if (current_pid != g_target_pid) return;
    if (copied > 0) pr_info("[KPM-GodMode] PID: %d [%s] -> %s\n", current_pid, sys_name, buf);
}

// ================== 核心拦截区 ==================

void before_openat(hook_fargs4_t *args, void *udata) { extract_and_log_path((const char __user *)syscall_argn(args, 1), "openat"); }
void before_faccessat(hook_fargs4_t *args, void *udata) { extract_and_log_path((const char __user *)syscall_argn(args, 1), "faccessat"); }
void before_execve(hook_fargs4_t *args, void *udata) { extract_and_log_path((const char __user *)syscall_argn(args, 0), "execve"); }
void before_unlinkat(hook_fargs4_t *args, void *udata) { extract_and_log_path((const char __user *)syscall_argn(args, 1), "unlinkat"); }

// 🌐 修复后的网络拦截逻辑
void before_connect(hook_fargs4_t *args, void *udata) {
    if (!is_target_pid()) return;
    
    int fd = (int)syscall_argn(args, 0);
    const void __user *uservaddr = (const void __user *)syscall_argn(args, 1);
    struct custom_sockaddr_in addr;
    
    // 如果我们成功找到了内核的拷贝函数，就解析 IP
    if (__my_copy_from_user) {
        // 返回 0 表示全部拷贝成功
        if (__my_copy_from_user(&addr, uservaddr, sizeof(struct custom_sockaddr_in)) == 0) {
            if (addr.sin_family == 2) { 
                unsigned short port = ((addr.sin_port & 0xFF) << 8) | ((addr.sin_port & 0xFF00) >> 8);
                unsigned char *ip_bytes = (unsigned char *)&addr.sin_addr;
                
                pr_info("[KPM-GodMode] 🌐 NET! PID: %d [connect] -> IP: %d.%d.%d.%d, Port: %d\n", 
                        g_target_pid, ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3], port);
                return;
            }
        }
    }
    
    // 如果找不到拷贝函数，或者不是 IPv4 协议，则退而求其次打印 FD
    pr_info("[KPM-GodMode] 🌐 NET! PID: %d [connect] -> fd: %d (Pointer: %px)\n", g_target_pid, fd, uservaddr);
}

void before_mprotect(hook_fargs4_t *args, void *udata) {
    if (!is_target_pid()) return;
    unsigned long start = (unsigned long)syscall_argn(args, 0);
    unsigned long len = (unsigned long)syscall_argn(args, 1);
    unsigned long prot = (unsigned long)syscall_argn(args, 2);
    if (prot & 4) {
        pr_info("[KPM-GodMode] 🧠 EXECUTABLE MEMORY! PID: %d [mprotect] -> Addr: %lx, Size: %lu, Prot: %lx\n", 
                g_target_pid, start, len, prot);
    }
}

void before_prctl(hook_fargs4_t *args, void *udata) {
    if (!is_target_pid()) return;
    long option = (long)syscall_argn(args, 0);
    if (option == 4) {
        long arg2 = (long)syscall_argn(args, 1);
        pr_info("[KPM-GodMode] 🛑 ANTI-DUMP! PID: %d [prctl(PR_SET_DUMPABLE)] -> value: %ld\n", g_target_pid, arg2);
    }
}

// 🛡️ 主动防御
void active_defense_after_hook(hook_fargs4_t *args, int path_arg_index) {
    if (!is_target_pid()) return;
    const char __user *filename = (const char __user *)syscall_argn(args, path_arg_index);
    char buf[256]; buf[0] = '\0';
    long copied = compat_strncpy_from_user(buf, filename, sizeof(buf) - 1);
    if (copied > 0 && copied < sizeof(buf)) buf[copied] = '\0';

    if (my_strstr(buf, "su") || my_strstr(buf, "magisk") || my_strstr(buf, "xposed") || my_strstr(buf, "frida")) {
        pr_info("[KPM-GodMode] 🛡️ BLOCKED DETECT: %s\n", buf);
        args->ret = -2; // 强行返回不存在
    }
}

void after_openat(hook_fargs4_t *args, void *udata) { active_defense_after_hook(args, 1); }
void after_faccessat(hook_fargs4_t *args, void *udata) { active_defense_after_hook(args, 1); }

// ================== 生命周期 ==================

static long monitor_init(const char *args, const char *event, void *__user reserved) {
    g_target_pkg[0] = '\0'; g_target_pid = -1; g_is_monitoring = 0;
    __task_pid_nr_ns_ptr = (typeof(__task_pid_nr_ns_ptr))kallsyms_lookup_name("__task_pid_nr_ns");

    // 🔥 核心改动：动态挖掘底层真实的内存拷贝函数
    __my_copy_from_user = (void *)kallsyms_lookup_name("_copy_from_user");
    if (!__my_copy_from_user) {
        __my_copy_from_user = (void *)kallsyms_lookup_name("__arch_copy_from_user");
    }

    fp_hook_syscalln(__NR_execve, 3, before_execve, 0, 0);
    fp_hook_syscalln(__NR_unlinkat, 3, before_unlinkat, 0, 0);
    fp_hook_syscalln(__NR_connect, 3, before_connect, 0, 0);
    fp_hook_syscalln(__NR_mprotect, 3, before_mprotect, 0, 0);
    fp_hook_syscalln(__NR_prctl, 5, before_prctl, 0, 0);
    fp_hook_syscalln(__NR_openat, 4, before_openat, after_openat, 0);
    fp_hook_syscalln(__NR_faccessat, 4, before_faccessat, after_faccessat, 0);
    
    pr_info("[KPM-GodMode] V7.1 Loaded.\n");
    return 0;
}

static long monitor_control0(const char *args, char *__user out_msg, int outlen) {
    if (args && args[0] != '\0') {
        my_strcpy(g_target_pkg, args, sizeof(g_target_pkg));
        g_target_pid = -1; g_is_monitoring = 1;
        pr_info("[KPM-GodMode] Sniper ON. Target: [%s]...\n", g_target_pkg);
    } else {
        g_is_monitoring = 0; g_target_pid = -1;
        pr_info("[KPM-GodMode] Stopped.\n");
    }
    return 0;
}

static long monitor_exit(void *__user reserved) {
    fp_unhook_syscalln(__NR_execve, before_execve, 0);
    fp_unhook_syscalln(__NR_unlinkat, before_unlinkat, 0);
    fp_unhook_syscalln(__NR_connect, before_connect, 0);
    fp_unhook_syscalln(__NR_mprotect, before_mprotect, 0);
    fp_unhook_syscalln(__NR_prctl, before_prctl, 0);
    fp_unhook_syscalln(__NR_openat, before_openat, after_openat);
    fp_unhook_syscalln(__NR_faccessat, before_faccessat, after_faccessat);
    pr_info("[KPM-GodMode] Exited.\n");
    return 0;
}

KPM_INIT(monitor_init);
KPM_CTL0(monitor_control0);
KPM_EXIT(monitor_exit);
