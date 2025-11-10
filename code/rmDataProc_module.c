#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/namei.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/delay.h>
#include <linux/kprobes.h>

#define MODULE_NAME "rmDataProc_module"
#define LOG_FILE "/tmp/rmDataProc_module.log"

// 全局变量
static struct file *log_file = NULL;
static DEFINE_SPINLOCK(log_lock);

// 允许的进程白名单
static const char *allowed_processes[] = {
    "com.sukisu.ultra",
    "bin.mt.plus",
    NULL
};

// 日志记录函数
static void log_message(const char *format, ...)
{
    va_list args;
    char buf[256];
    mm_segment_t old_fs;
    int len;
    struct timespec64 ts;
    
    va_start(args, format);
    len = vsnprintf(buf, sizeof(buf), format, args);
    va_end(args);
    
    if (len > 0) {
        spin_lock(&log_lock);
        
        // 获取当前时间
        ktime_get_real_ts64(&ts);
        
        old_fs = get_fs();
        set_fs(KERNEL_DS);
        
        if (log_file && log_file->f_op && log_file->f_op->write) {
            // 添加时间戳到日志
            char time_buf[300];
            int time_len = snprintf(time_buf, sizeof(time_buf), "[%lld.%09ld] %s", 
                                   (long long)ts.tv_sec, ts.tv_nsec, buf);
            if (time_len > 0) {
                log_file->f_op->write(log_file, time_buf, time_len, &log_file->f_pos);
            }
        }
        
        set_fs(old_fs);
        spin_unlock(&log_lock);
    }
}

// 检查进程是否在白名单中
static int is_process_allowed(const char *cmdline)
{
    int i;
    
    if (!cmdline)
        return 0;
    
    for (i = 0; allowed_processes[i] != NULL; i++) {
        if (strstr(cmdline, allowed_processes[i])) {
            return 1;
        }
    }
    
    return 0;
}

// 检查路径是否在/data/data/或/data/user/0/目录下且与cmdline匹配
static int is_path_allowed(const char *path, const char *cmdline)
{
    char expected_path1[256];
    char expected_path2[256];
    
    if (!path || !cmdline)
        return 0;
    
    // 构建预期的路径模式
    snprintf(expected_path1, sizeof(expected_path1), "/data/data/%s", cmdline);
    snprintf(expected_path2, sizeof(expected_path2), "/data/user/0/%s", cmdline);
    
    // 检查路径是否匹配预期模式
    if (strncmp(path, expected_path1, strlen(expected_path1)) == 0 ||
        strncmp(path, expected_path2, strlen(expected_path2)) == 0) {
        return 1;
    }
    
    return 0;
}

// 检查是否是/apex目录
static int is_apex_directory(const char *path)
{
    return path && (strncmp(path, "/apex/", 6) == 0);
}

// 检查是否是/data目录
static int is_data_directory(const char *path)
{
    return path && (strncmp(path, "/data/", 6) == 0);
}

// 获取进程的cmdline
static int get_process_cmdline(struct task_struct *task, char *buffer, int buffer_len)
{
    struct mm_struct *mm;
    int res = 0;
    
    if (!task || !buffer || buffer_len <= 0)
        return 0;
    
    mm = get_task_mm(task);
    if (!mm)
        return 0;
    
    if (mm->arg_end) {
        unsigned long len = mm->arg_end - mm->arg_start;
        if (len > buffer_len - 1)
            len = buffer_len - 1;
        
        if (copy_from_user(buffer, (const char __user *)mm->arg_start, len)) {
            res = 0;
        } else {
            buffer[len] = '\0';
            res = 1;
        }
    }
    
    mmput(mm);
    return res;
}

// 获取进程名称
static void get_process_name(struct task_struct *task, char *buffer, int buffer_len)
{
    if (!task || !buffer || buffer_len <= 0)
        return;
    
    get_task_comm(buffer, task);
}

// kprobe处理函数
static int handler_pre(struct kprobe *p, struct pt_regs *regs)
{
    struct path *path;
    char filename[256];
    char cmdline[256];
    char proc_name[16];
    struct task_struct *current_task;
    int allowed = 0;
    int is_data_dir = 0;
    int is_apex_dir = 0;
    
    // 获取当前进程
    current_task = current;
    
    // 获取要删除的文件路径
    path = (struct path *)regs->di;
    if (IS_ERR(path) || !path)
        return 0;
    
    // 将路径转换为字符串
    memset(filename, 0, sizeof(filename));
    d_path(path, filename, sizeof(filename) - 1);
    
    // 获取进程cmdline和名称
    memset(cmdline, 0, sizeof(cmdline));
    memset(proc_name, 0, sizeof(proc_name));
    get_process_cmdline(current_task, cmdline, sizeof(cmdline) - 1);
    get_process_name(current_task, proc_name, sizeof(proc_name) - 1);
    
    is_data_dir = is_data_directory(filename);
    is_apex_dir = is_apex_directory(filename);
    
    // 检查是否是/data/目录下的删除操作
    if (is_data_dir) {
        // 检查进程是否在白名单中
        if (is_process_allowed(cmdline)) {
            allowed = 1;
            log_message("[ALLOWED] Process %s (PID: %d, Name: %s) deleted %s - Whitelisted process\n", 
                       cmdline, current_task->pid, proc_name, filename);
        }
        // 检查路径是否与cmdline匹配
        else if (is_path_allowed(filename, cmdline)) {
            allowed = 1;
            log_message("[ALLOWED] Process %s (PID: %d, Name: %s) deleted %s - Path matches cmdline\n", 
                       cmdline, current_task->pid, proc_name, filename);
        }
        else {
            log_message("[VIOLATION] Process %s (PID: %d, Name: %s) deleted %s - Data directory violation (would be blocked)\n", 
                       cmdline, current_task->pid, proc_name, filename);
        }
    }
    
    // 检查是否是/apex目录下的删除操作
    if (is_apex_dir) {
        log_message("[VIOLATION] Process %s (PID: %d, Name: %s) deleted %s - Apex directory violation (would be suspended)\n", 
                   cmdline, current_task->pid, proc_name, filename);
    }
    
    return 0; // 始终允许操作，只记录日志
}

static struct kprobe rm_kprobe = {
    .symbol_name = "security_inode_unlink",
    .pre_handler = handler_pre,
};

// 模块初始化
static int __init rm_monitor_init(void)
{
    int ret;
    struct path log_path;
    
    printk(KERN_INFO "rmDataProc_module: Initializing...\n");
    
    // 打开日志文件
    ret = kern_path(LOG_FILE, LOOKUP_OPEN, &log_path);
    if (ret) {
        // 如果文件不存在，创建它
        struct file *f = filp_open(LOG_FILE, O_CREAT | O_WRONLY | O_APPEND, 0644);
        if (IS_ERR(f)) {
            printk(KERN_ERR "rmDataProc_module: Failed to create log file\n");
            return PTR_ERR(f);
        }
        log_file = f;
    } else {
        struct file *f = dentry_open(&log_path, O_WRONLY | O_APPEND, current_cred());
        if (IS_ERR(f)) {
            printk(KERN_ERR "rmDataProc_module: Failed to open log file\n");
            return PTR_ERR(f);
        }
        log_file = f;
    }
    
    // 注册kprobe
    ret = register_kprobe(&rm_kprobe);
    if (ret < 0) {
        printk(KERN_ERR "rmDataProc_module: Failed to register kprobe, error %d\n", ret);
        if (log_file)
            filp_close(log_file, NULL);
        return ret;
    }
    
    log_message("=== rmDataProc_module started (LOG ONLY MODE) ===\n");
    printk(KERN_INFO "rmDataProc_module: Successfully loaded (log only mode)\n");
    
    return 0;
}

// 模块退出
static void __exit rm_monitor_exit(void)
{
    printk(KERN_INFO "rmDataProc_module: Unloading...\n");
    
    // 取消注册kprobe
    unregister_kprobe(&rm_kprobe);
    
    // 关闭日志文件
    if (log_file) {
        log_message("=== rmDataProc_module stopped ===\n");
        filp_close(log_file, NULL);
    }
    
    printk(KERN_INFO "rmDataProc_module: Successfully unloaded\n");
}

module_init(rm_monitor_init);
module_exit(rm_monitor_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Your Name");
MODULE_DESCRIPTION("Monitor file deletion operations (log only)");
MODULE_VERSION("1.0");