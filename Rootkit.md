# Rootkit

파일, 폴더, 프로세스를 숨기는데 사용되는 크레킹 도구이다.

LKM(Loadable Kernel Module) 루트킷이란 커널이 제공하는 시스템콜을 가로채서 공격자가 만든 시스템콜을 수행하도록 하는 루트킷이다. 전역변수로 정의된 `sys_call_table`에 정의된 시스템콜 함수의 주소를 참조해서 호출된다. 루트킷은 `sys_call_table`이 저장하고 있는 시스템콜 함수의 주소값을 변경해서 공격자의 시스템콜이 호출되도록 한다.

[LKM 루트킷](http://visu4l.tistory.com/56)

## 목표 시스템

| 운영체제                | 커널 버전         |
| :---                    | :---              |
| Ubuntu 12.04 LTS 32-bit | 3.13.0-32-generic |

## `getdents()`

```
int getdents(unsigned int fd, struct dirent *dirp, unsigned int count);
```

| 변수  | 설명                       |
| :---  |                       ---: |
| fd    | file descriptor            |
| dirp  | pointer that points buffer |
| count | size of the buffer         |

`getdents()` 함수는 읽어들인 바이트 수를 반환한다. 디렉토리 끝에서는 0을 반환하고 에러가 발생한 경우에는 -1을 반환한다.

[getdents() - man7](http://man7.org/linux/man-pages/man2/getdents.2.html)  
[getdents() - tutorialspoint](http://www.tutorialspoint.com/unix_system_calls/getdents.htm)

## `current` 매크로

프로세스 디스크립터의 주소값을 가진 포인터 변수

> 프로세스틑 실행 상태에 있는 프로그램의 인스턴스(instance)로 정의된다. (중략)
> 리눅스 소스코드에서는 프로세스를 가리켜 '태스크(task)'라 부르기도 한다.
>

### 프로세스 디스크립터
프로세스의 정보를 담는 자료구조이다. 프로세스의 우선순위, 상태, 주소 공간 위치 등을 담고 있다. 운영체제 시간에 배우는 PCB(Process Control Block)과 동치라고 이해해도 되겠다. 리눅스에서는 `task_struct` 구조체를 사용하고 있다.

```
d_inode = current->files->fdt->fd[fd]->f_path.dentry->d_inode;
```

### `Linux/include/linux/sched.h`

```
1042 struct task_struct {

... (중략) ...

1214 /* open file information */
1215         struct files_struct *files;

... (후략) ...

1457 };
```

### `Linux/include/linux/fdtable.h`
```
 45 struct files_struct {
 46   /*
 47    * read mostly part
 48    */
 49         atomic_t count;
 50         struct fdtable __rcu *fdt;
 51         struct fdtable fdtab;
 52   /*
 53    * written part on a separate cache line in SMP
 54    */
 55         spinlock_t file_lock ____cacheline_aligned_in_smp;
 56         int next_fd;
 57         unsigned long close_on_exec_init[1];
 58         unsigned long open_fds_init[1];
 59         struct file __rcu * fd_array[NR_OPEN_DEFAULT];
 60 };
```

### `Linux/include/linux/fdtable.h`
```
 24 struct fdtable {
 25         unsigned int max_fds;
 26         struct file __rcu **fd;      /* current fd array */
 27         unsigned long *close_on_exec;
 28         unsigned long *open_fds;
 29         struct rcu_head rcu;
 30 };
```

### `Linux/include/linux/fs.h`

```
772 struct file {
773         union {
774                 struct llist_node       fu_llist;
775                 struct rcu_head         fu_rcuhead;
776         } f_u;
777         struct path             f_path;
778 #define f_dentry        f_path.dentry
779         struct inode            *f_inode;       /* cached value */
780         const struct file_operations    *f_op;
781
782         /*
783          * Protects f_ep_links, f_flags, f_pos vs i_size in lseek SEEK_CUR.
784          * Must not be taken from IRQ context.
785          */
786         spinlock_t              f_lock;
787         atomic_long_t           f_count;
788         unsigned int            f_flags;
789         fmode_t                 f_mode;
790         loff_t                  f_pos;
791         struct fown_struct      f_owner;
792         const struct cred       *f_cred;
793         struct file_ra_state    f_ra;
794
795         u64                     f_version;
796 #ifdef CONFIG_SECURITY
797         void                    *f_security;
798 #endif
799         /* needed for tty driver, and maybe others */
800         void                    *private_data;
801
802 #ifdef CONFIG_EPOLL
803         /* Used by fs/eventpoll.c to link all the hooks to this file */
804         struct list_head        f_ep_links;
805         struct list_head        f_tfile_llink;
806 #endif /* #ifdef CONFIG_EPOLL */
807         struct address_space    *f_mapping;
808 #ifdef CONFIG_DEBUG_WRITECOUNT
809         unsigned long f_mnt_write_state;
810 #endif
811 };
```

### `Linux/include/linux/path.h`
```
  7 struct path {
  8         struct vfsmount *mnt;
  9         struct dentry *dentry;
 10 };
```

### `Linux/include/linux/dcache.h`
```
108 struct dentry {
109         /* RCU lookup touched fields */
110         unsigned int d_flags;           /* protected by d_lock */
111         seqcount_t d_seq;               /* per dentry seqlock */
112         struct hlist_bl_node d_hash;    /* lookup hash list */
113         struct dentry *d_parent;        /* parent directory */
114         struct qstr d_name;
115         struct inode *d_inode;          /* Where the name belongs to - NULL is
116                                          * negative */
117         unsigned char d_iname[DNAME_INLINE_LEN];        /* small names */
118
119         /* Ref lookup also touches following */
120         struct lockref d_lockref;       /* per-dentry lock and refcount */
121         const struct dentry_operations *d_op;
122         struct super_block *d_sb;       /* The root of the dentry tree */
123         unsigned long d_time;           /* used by d_revalidate */
124         void *d_fsdata;                 /* fs-specific data */
125
126         struct list_head d_lru;         /* LRU list */
127         /*
128          * d_child and d_rcu can share memory
129          */
130         union {
131                 struct list_head d_child;       /* child of parent list */
132                 struct rcu_head d_rcu;
133         } d_u;
134         struct list_head d_subdirs;     /* our children */
135         struct hlist_node d_alias;      /* inode alias list */
136 };
```

### `Linux/include/linux/fs.h`
```
519 /*
520  * Keep mostly read-only and often accessed (especially for
521  * the RCU path lookup and 'stat' data) fields at the beginning
522  * of the 'struct inode'
523  */
524 struct inode {
525         umode_t                 i_mode;
526         unsigned short          i_opflags;
527         kuid_t                  i_uid;
528         kgid_t                  i_gid;
529         unsigned int            i_flags;
530
531 #ifdef CONFIG_FS_POSIX_ACL
532         struct posix_acl        *i_acl;
533         struct posix_acl        *i_default_acl;
534 #endif
535
536         const struct inode_operations   *i_op;
537         struct super_block      *i_sb;
538         struct address_space    *i_mapping;
539
540 #ifdef CONFIG_SECURITY
541         void                    *i_security;
542 #endif
543
544         /* Stat data, not accessed from path walking */
545         unsigned long           i_ino;
546         /*
547          * Filesystems may only read i_nlink directly.  They shall use the
548          * following functions for modification:
549          *
550          *    (set|clear|inc|drop)_nlink
551          *    inode_(inc|dec)_link_count
552          */
553         union {
554                 const unsigned int i_nlink;
555                 unsigned int __i_nlink;
556         };
557         dev_t                   i_rdev;
558         loff_t                  i_size;
559         struct timespec         i_atime;
560         struct timespec         i_mtime;
561         struct timespec         i_ctime;
562         spinlock_t              i_lock; /* i_blocks, i_bytes, maybe i_size */
563         unsigned short          i_bytes;
564         unsigned int            i_blkbits;
565         blkcnt_t                i_blocks;
566
567 #ifdef __NEED_I_SIZE_ORDERED
568         seqcount_t              i_size_seqcount;
569 #endif
570
571         /* Misc */
572         unsigned long           i_state;
573         struct mutex            i_mutex;
574
575         unsigned long           dirtied_when;   /* jiffies of first dirtying */
576
577         struct hlist_node       i_hash;
578         struct list_head        i_wb_list;      /* backing dev IO list */
579         struct list_head        i_lru;          /* inode LRU list */
580         struct list_head        i_sb_list;
581         union {
582                 struct hlist_head       i_dentry;
583                 struct rcu_head         i_rcu;
584         };
585         u64                     i_version;
586         atomic_t                i_count;
587         atomic_t                i_dio_count;
588         atomic_t                i_writecount;
589         const struct file_operations    *i_fop; /* former ->i_op->default_file_ops */
590         struct file_lock        *i_flock;
591         struct address_space    i_data;
592 #ifdef CONFIG_QUOTA
593         struct dquot            *i_dquot[MAXQUOTAS];
594 #endif
595         struct list_head        i_devices;
596         union {
597                 struct pipe_inode_info  *i_pipe;
598                 struct block_device     *i_bdev;
599                 struct cdev             *i_cdev;
600         };
601
602         __u32                   i_generation;
603
604 #ifdef CONFIG_FSNOTIFY
605         __u32                   i_fsnotify_mask; /* all events this inode cares about */
606         struct hlist_head       i_fsnotify_marks;
607 #endif
608
609 #ifdef CONFIG_IMA
610         atomic_t                i_readcount; /* struct files open RO */
611 #endif
612         void                    *i_private; /* fs or device private pointer */
613 };
614
615 static inline int inode_unhashed(struct inode *inode)
616 {
617         return hlist_unhashed(&inode->i_hash);
618 }
```

### `diamorphine.c` 분석

```
kdirent = kzalloc(ret, GFP_KERNEL);
if (kdirent == NULL)
	return ret;
```

### `Linux/include/linux/slab.h`
```
441 static __always_inline void *kmalloc(size_t size, gfp_t flags)
442 {
443         if (__builtin_constant_p(size)) {
444                 if (size > KMALLOC_MAX_CACHE_SIZE)
445                         return kmalloc_large(size, flags);
446 #ifndef CONFIG_SLOB
447                 if (!(flags & GFP_DMA)) {
448                         int index = kmalloc_index(size);
449
450                         if (!index)
451                                 return ZERO_SIZE_PTR;
452
453                         return kmem_cache_alloc_trace(kmalloc_caches[index],
454                                         flags, size);
455                 }
456 #endif
457         }
458         return __kmalloc(size, flags);
459 }

... (중략) ...

633 static inline void *kzalloc(size_t size, gfp_t flags)
634 {
635         return kmalloc(size, flags | __GFP_ZERO);
636 }
```

GFP(Get Free Pages)

### `Linux/include/linux/gfp.h`
```
 80 #define __GFP_ZERO      ((__force gfp_t)___GFP_ZERO)    /* Return zeroed page on success */

... (중략) ...

 111 #define GFP_KERNEL      (__GFP_WAIT | __GFP_IO | __GFP_FS)
```

### `Linux/arch/x86/include/asm/uaccess.h`

```
587 static inline unsigned long __must_check
588 copy_from_user(void *to, const void __user *from, unsigned long n)
589 {
590         int sz = __compiletime_object_size(to);
591
592         might_fault();
593
594         /*
595          * While we would like to have the compiler do the checking for us
596          * even in the non-constant size case, any false positives there are
597          * a problem (especially when DEBUG_STRICT_USER_COPY_CHECKS, but even
598          * without - the [hopefully] dangerous looking nature of the warning
599          * would make people go look at the respecitive call sites over and
600          * over again just to find that there's no problem).
601          *
602          * And there are cases where it's just not realistic for the compiler
603          * to prove the count to be in range. For example when multiple call
604          * sites of a helper function - perhaps in different source files -
605          * all doing proper range checking, yet the helper function not doing
606          * so again.
607          *
608          * Therefore limit the compile time checking to the constant size
609          * case, and do only runtime checking for non-constant sizes.
610          */
611
612         if (likely(sz < 0 || sz >= n))
613                 n = _copy_from_user(to, from, n);
614         else if(__builtin_constant_p(n))
615                 copy_from_user_overflow();
616         else
617                 __copy_from_user_overflow(sz, n);
618
619         return n;
620 }
```

`copy_from_user()` 함수는 복사하지 못한 데이터의 바이트 수를 반환한다.

[copy_from_user() 함수 manpage](http://mirror.linux.org.au/linux-mandocs/2.5.72/copy_from_user.html)

### module 구조체

```
229 struct module
230 {
231         enum module_state state;
232
233         /* Member of list of modules */
234         struct list_head list;
235
236         /* Unique handle for this module */
237         char name[MODULE_NAME_LEN];
238
239         /* Sysfs stuff. */
240         struct module_kobject mkobj;
241         struct module_attribute *modinfo_attrs;
242         const char *version;
243         const char *srcversion;
244         struct kobject *holders_dir;
245
246         /* Exported symbols */
247         const struct kernel_symbol *syms;
248         const unsigned long *crcs;
249         unsigned int num_syms;
250
251         /* Kernel parameters. */
252         struct kernel_param *kp;
253         unsigned int num_kp;
254
255         /* GPL-only exported symbols. */
256         unsigned int num_gpl_syms;
257         const struct kernel_symbol *gpl_syms;
258         const unsigned long *gpl_crcs;
259
260 #ifdef CONFIG_UNUSED_SYMBOLS
261         /* unused exported symbols. */
262         const struct kernel_symbol *unused_syms;
263         const unsigned long *unused_crcs;
264         unsigned int num_unused_syms;
265
266         /* GPL-only, unused exported symbols. */
267         unsigned int num_unused_gpl_syms;
268         const struct kernel_symbol *unused_gpl_syms;
269         const unsigned long *unused_gpl_crcs;
270 #endif
271
272 #ifdef CONFIG_MODULE_SIG
273         /* Signature was verified. */
274         bool sig_ok;
275 #endif
276
277         /* symbols that will be GPL-only in the near future. */
278         const struct kernel_symbol *gpl_future_syms;
279         const unsigned long *gpl_future_crcs;
280         unsigned int num_gpl_future_syms;
281
282         /* Exception table */
283         unsigned int num_exentries;
284         struct exception_table_entry *extable;
285
286         /* Startup function. */
287         int (*init)(void);
288
289         /* If this is non-NULL, vfree after init() returns */
290         void *module_init;
291
292         /* Here is the actual code + data, vfree'd on unload. */
293         void *module_core;
294
295         /* Here are the sizes of the init and core sections */
296         unsigned int init_size, core_size;
297
298         /* The size of the executable code in each section.  */
299         unsigned int init_text_size, core_text_size;
300
301         /* Size of RO sections of the module (text+rodata) */
302         unsigned int init_ro_size, core_ro_size;
303
304         /* Arch-specific module values */
305         struct mod_arch_specific arch;
306
307         unsigned int taints;    /* same bits as kernel:tainted */
308
309 #ifdef CONFIG_GENERIC_BUG
310         /* Support for BUG */
311         unsigned num_bugs;
312         struct list_head bug_list;
313         struct bug_entry *bug_table;
314 #endif
315
316 #ifdef CONFIG_KALLSYMS
317         /*
318          * We keep the symbol and string tables for kallsyms.
319          * The core_* fields below are temporary, loader-only (they
320          * could really be discarded after module init).
321          */
322         Elf_Sym *symtab, *core_symtab;
323         unsigned int num_symtab, core_num_syms;
324         char *strtab, *core_strtab;
325
326         /* Section attributes */
327         struct module_sect_attrs *sect_attrs;
328
329         /* Notes attributes */
330         struct module_notes_attrs *notes_attrs;
331 #endif
332
333         /* The command line arguments (may be mangled).  People like
334            keeping pointers to this stuff */
335         char *args;
336
337 #ifdef CONFIG_SMP
338         /* Per-cpu data. */
339         void __percpu *percpu;
340         unsigned int percpu_size;
341 #endif
342
343 #ifdef CONFIG_TRACEPOINTS
344         unsigned int num_tracepoints;
345         struct tracepoint * const *tracepoints_ptrs;
346 #endif
347 #ifdef HAVE_JUMP_LABEL
348         struct jump_entry *jump_entries;
349         unsigned int num_jump_entries;
350 #endif
351 #ifdef CONFIG_TRACING
352         unsigned int num_trace_bprintk_fmt;
353         const char **trace_bprintk_fmt_start;
354 #endif
355 #ifdef CONFIG_EVENT_TRACING
356         struct ftrace_event_call **trace_events;
357         unsigned int num_trace_events;
358 #endif
359 #ifdef CONFIG_FTRACE_MCOUNT_RECORD
360         unsigned int num_ftrace_callsites;
361         unsigned long *ftrace_callsites;
362 #endif
363
364 #ifdef CONFIG_MODULE_UNLOAD
365         /* What modules depend on me? */
366         struct list_head source_list;
367         /* What modules do I depend on? */
368         struct list_head target_list;
369
370         /* Destruction function. */
371         void (*exit)(void);
372
373         struct module_ref __percpu *refptr;
374 #endif
375
376 #ifdef CONFIG_CONSTRUCTORS
377         /* Constructor functions. */
378         ctor_fn_t *ctors;
379         unsigned int num_ctors;
380 #endif
381 };
```

## Control register
[Wikipedia - Control register](https://en.wikipedia.org/wiki/Control_register)
