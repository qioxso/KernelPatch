#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <uapi/asm-generic/unistd.h>
#include <linux/uaccess.h>
#include <syscall.h>
#include <kputils.h>
#include <asm/current.h>

KPM_NAME("kpm-stealth-monitor");
KPM_VERSION("10.0.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("Custom");
KPM_DESCRIPTION("V10 Absolute Lock via prctl(PR_SET_NAME)");

char g_target_pkg[64];    
pid_t g_target_tgid = -1; 
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

// ================== 🔥 V10 核心：性能起飞的提取器 ==================
void extract_and_log_path(const char __user *filename, const char *sys_name) {
    // 只有绝对锁定了真正的 App，才去读取内存路径，彻底消除系统卡顿！
    if (!is_target_tgid()) return;

    char buf[512]; buf[0] = '\0';
    long copied = compat_strncpy_from_user(buf, filename, sizeof(buf) - 1);
    if (copied > 0 && copied < sizeof(buf)) buf[copied] = '\0'; else buf[0] = '\0';

    if (copied > 0) pr_info("[KPM-V10] TID: %d [%s] -> %s\n", get_current_tid(), sys_name, buf);
}

// ================== 核心拦截区 ==================

void before_openat(hook_fargs4_t *args, void *udata) { extract_and_log_path((const char __user *)syscall_argn(args, 1), "openat"); }
void before_faccessat(hook_fargs4_t *args, void *udata) { extract_and_log_path((const char __user *)syscall_argn(args, 1), "faccessat"); }
void before_execve(hook_fargs4_t *args, void *udata) { extract_and_log_path((const char __user *)syscall_argn(args, 0), "execve"); }
void before_unlinkat(hook_fargs4_t *args, void *udata) { extract_and_log_path((const char __user *)syscall_argn(args, 1), "unlinkat"); }

// 📦 载荷转移监控
void before_renameat(hook_fargs4_t *args, void *udata) {
    if (!is_target_tgid()) return;
    char old_buf[256]; old_buf[0] = '\0'; char new_buf[256]; new_buf[0] = '\0';
    long c1 = compat_strncpy_from_user(old_buf, (const char __user *)syscall_argn(args, 1), sizeof(old_buf) - 1);
    long c2 = compat_strncpy_from_user(new_buf, (const char __user *)syscall_argn(args, 3), sizeof(new_buf) - 1);
    if (c1 > 0 && c1 < sizeof(old_buf)) old_buf[c1] = '\0';
    if (c2 > 0 && c2 < sizeof(new_buf)) new_buf[c2] = '\0';
    pr_info("[KPM-V10] 📦 RENAME! TID: %d [renameat] -> From: %s, To: %s\n", get_current_tid(), old_buf, new_buf);
}

void before_kill(hook_fargs4_t *args, void *udata) {
    if (!is_target_tgid()) return;
    pr_info("[KPM-V10] 🗡️ KILL SIGNAL! TID: %d [kill] -> Target PID: %d, Signal: %d\n", 
            get_current_tid(), (pid_t)syscall_argn(args, 0), (int)syscall_argn(args, 1));
}

// 🌐 网络监控
void before_connect(hook_fargs4_t *args, void *udata) {
    if (!is_target_tgid()) return;
    const void __user *uservaddr = (const void __user *)syscall_argn(args, 1);
    struct custom_sockaddr_in addr;
    if (__my_copy_from_user && __my_copy_from_user(&addr, uservaddr, sizeof(struct custom_sockaddr_in)) == 0) {
        if (addr.sin_family == 2) { 
            unsigned short port = ((addr.sin_port & 0xFF) << 8) | ((addr.sin_port & 0xFF00) >> 8);
            unsigned char *ip = (unsigned char *)&addr.sin_addr;
            pr_info("[KPM-V10] 🌐 NET! TID: %d [connect] -> IP: %d.%d.%d.%d, Port: %d\n", get_current_tid(), ip[0], ip[1], ip[2], ip[3], port);
        }
    }
}

void before_mprotect(hook_fargs4_t *args, void *udata) {
    if (!is_target_tgid()) return;
    unsigned long prot = (unsigned long)syscall_argn(args, 2);
    if (prot & 4) {
        pr_info("[KPM-V10] 🧠 EXEC MEM! TID: %d [mprotect] -> Addr: %lx, Size: %lu, Prot: %lx\n", 
                get_current_tid(), (unsigned long)syscall_argn(args, 0), (unsigned long)syscall_argn(args, 1), prot);
    }
}

// 🎯 🔥 V10 终极制导逻辑：拦截 prctl(PR_SET_NAME)
void before_prctl(hook_fargs4_t *args, void *udata) {
    long option = (long)syscall_argn(args, 0);

    // 15 = PR_SET_NAME。只有 App 从 Zygote 孵化时才会把名字改成包名
    if (option == 15 && g_target_tgid == -1 && g_target_pkg[0] != '\0') {
        const char __user *name_ptr = (const char __user *)syscall_argn(args, 1);
        char thread_name[16]; thread_name[0] = '\0';
        long copied = compat_strncpy_from_user(thread_name, name_ptr, 15);
        
        if (copied > 0) {
            thread_name[copied] = '\0';
            // 对比前 15 个字符是否与目标包名匹配
            int match = 1;
            for (int i = 0; i < 15; i++) {
                if (thread_name[i] == '\0' || g_target_pkg[i] == '\0') break;
                if (thread_name[i] != g_target_pkg[i]) { match = 0; break; }
            }
            if (match) {
                g_target_tgid = get_current_tgid();
                pr_info("[KPM-V10] 🎯 PERFECT LOCK! Zygote hatched [%s]. Locked TGID: %d\n", thread_name, g_target_tgid);
            }
        }
    }

    if (!is_target_tgid()) return;
    if (option == 4) pr_info("[KPM-V10] 🛑 ANTI-DUMP! TID: %d [prctl(PR_SET_DUMPABLE)]\n", get_current_tid());
}

// 🛡️ 主动防御区
void active_defense_after_hook(hook_fargs4_t *args, int path_arg_index) {
    if (!is_target_tgid()) return;
    const char __user *filename = (const char __user *)syscall_argn(args, path_arg_index);
    char buf[256]; buf[0] = '\0';
    long copied = compat_strncpy_from_user(buf, filename, sizeof(buf) - 1);
    if (copied > 0 && copied < sizeof(buf)) buf[copied] = '\0';

    if (my_strstr(buf, "su") || my_strstr(buf, "magisk") || my_strstr(buf, "xposed") || my_strstr(buf, "frida")) {
        pr_info("[KPM-V10] 🛡️ BLOCKED DETECT: %s\n", buf);
        args->ret = -2; //
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

    fp_hook_syscalln(__NR_execve, 3, before_execve, 0, 0);
    fp_hook_syscalln(__NR_unlinkat, 3, before_unlinkat, 0, 0);
    fp_hook_syscalln(__NR_connect, 3, before_connect, 0, 0);
    fp_hook_syscalln(__NR_mprotect, 3, before_mprotect, 0, 0);
    fp_hook_syscalln(__NR_prctl, 5, before_prctl, 0, 0);
    fp_hook_syscalln(__NR_renameat, 4, before_renameat, 0, 0);
    fp_hook_syscalln(__NR_kill, 2, before_kill, 0, 0);

    fp_hook_syscalln(__NR_openat, 4, before_openat, after_openat, 0);
    fp_hook_syscalln(__NR_faccessat, 4, before_faccessat, after_faccessat, 0);
    
    pr_info("[KPM-V10] Loaded. PR_SET_NAME Auto-Sniper Enabled.\n");
    return 0;
}

static long monitor_control0(const char *args, char *__user out_msg, int outlen) {
    if (args && args[0] != '\0') {
        my_strcpy(g_target_pkg, args, sizeof(g_target_pkg));
        g_target_tgid = -1; g_is_monitoring = 1;
        pr_info("[KPM-V10] Sniper ON. ⚠️ IMPORTANT: Now click to launch App [%s]!\n", g_target_pkg);
    } else {
        g_is_monitoring = 0; g_target_tgid = -1;
        pr_info("[KPM-V10] Stopped.\n");
    }
    return 0;
}

static long monitor_exit(void *__user reserved) {
    fp_unhook_syscalln(__NR_execve, before_execve, 0);
    fp_unhook_syscalln(__NR_unlinkat, before_unlinkat, 0);
    fp_unhook_syscalln(__NR_connect, before_connect, 0);
    fp_unhook_syscalln(__NR_mprotect, before_mprotect, 0);
    fp_unhook_syscalln(__NR_prctl, before_prctl, 0);
    fp_unhook_syscalln(__NR_renameat, before_renameat, 0);
    fp_unhook_syscalln(__NR_kill, before_kill, 0);
    fp_unhook_syscalln(__NR_openat, before_openat, after_openat);
    fp_unhook_syscalln(__NR_faccessat, before_faccessat, after_faccessat);
    pr_info("[KPM-V10] Exited.\n");
    return 0;
}

KPM_INIT(monitor_init);
KPM_CTL0(monitor_control0);
KPM_EXIT(monitor_exit);
