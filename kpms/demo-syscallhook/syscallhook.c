#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <uapi/asm-generic/unistd.h>
#include <linux/uaccess.h>
#include <syscall.h>
#include <linux/string.h>
#include <kputils.h>
#include <asm/current.h>

KPM_NAME("kpm-stealth-monitor"); // 名字改了，以防混淆
KPM_VERSION("2.0.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("Custom");
KPM_DESCRIPTION("Dynamic APK Syscall Monitor");

// 全局变量，用于动态存储目标包名
char g_target_pkg[16]; 
int g_is_monitoring = 0; // 0: 待命状态, 1: 监控状态

enum pid_type { PIDTYPE_PID, PIDTYPE_TGID, PIDTYPE_PGID, PIDTYPE_SID, PIDTYPE_MAX };
struct pid_namespace;

pid_t (*__task_pid_nr_ns_ptr)(struct task_struct *task, enum pid_type type, struct pid_namespace *ns) = 0;
void (*__get_task_comm_ptr)(char *buf, struct task_struct *tsk) = 0;

// 自定义的安全字符串拷贝，绝不会触发底层隐式调用
void safe_strcpy_15(char *dest, const char *src) {
    int i;
    for (i = 0; i < 15; i++) {
        if (!src || src[i] == '\0') break;
        dest[i] = src[i];
    }
    dest[i] = '\0';
}

void before_openat_monitor(hook_fargs4_t *args, void *udata)
{
    // 如果没有开启监控，立刻放行，保证系统极速运行
    if (g_is_monitoring == 0) return;

    struct task_struct *task = current;
    char comm[16];
    comm[0] = '\0';

    if (__get_task_comm_ptr) {
        __get_task_comm_ptr(comm, task);
        comm[15] = '\0';
    }

    // 比较进程名是否与我们动态设置的包名一致
    if (strncmp(comm, g_target_pkg, 15) != 0) {
        return; 
    }

    // 命中目标！开始解析参数
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

    pid_t pid = -1;
    if (__task_pid_nr_ns_ptr) {
        pid = __task_pid_nr_ns_ptr(task, PIDTYPE_PID, 0);
    }

    if (copied > 0) {
        pr_info("[KPM-Stealth] App: %s (PID: %d) openat -> %s\n", comm, pid, buf);
    }
}

static long monitor_init(const char *args, const char *event, void *__user reserved)
{
    g_target_pkg[0] = '\0';
    g_is_monitoring = 0;

    __task_pid_nr_ns_ptr = (typeof(__task_pid_nr_ns_ptr))kallsyms_lookup_name("__task_pid_nr_ns");
    __get_task_comm_ptr = (typeof(__get_task_comm_ptr))kallsyms_lookup_name("get_task_comm");

    if (!__get_task_comm_ptr) {
        pr_err("[KPM-Stealth] Error: Cannot find 'get_task_comm'\n");
        return -1;
    }

    // 模块一加载就挂载 Hook，但处于“待命”状态
    hook_err_t err = fp_hook_syscalln(__NR_openat, 4, before_openat_monitor, 0, 0);
    if (err) {
        pr_err("[KPM-Stealth] Hook failed: %d\n", err);
    } else {
        pr_info("[KPM-Stealth] Loaded and waiting for target via control0...\n");
    }

    return 0;
}

// 核心改动：利用 control0 动态修改监控目标
static long monitor_control0(const char *args, char *__user out_msg, int outlen)
{
    if (args && strlen(args) > 0) {
        // 安全地将传入的参数（如 com.tencent.mobileqq）截断并复制到全局变量中
        safe_strcpy_15(g_target_pkg, args);
        g_is_monitoring = 1;
        pr_info("[KPM-Stealth] Target locked! Now monitoring: %s\n", g_target_pkg);
    } else {
        g_is_monitoring = 0;
        pr_info("[KPM-Stealth] Target cleared. Monitoring paused.\n");
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
