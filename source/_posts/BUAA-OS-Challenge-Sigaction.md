---
title: BUAA-OS-Sigaction-Challenge
date: 2024-06-30
updated:
tags: BUAA-OS
categories: 学习
keywords: BUAA, OS, challenge, 挑战性任务
description: 2024年北航操作系统Sigaction挑战性任务的实验报告
top_img:
comments: 123123112312312312312312323
cover:
toc:
toc_number:
toc_style_simple:
copyright:
copyright_author:
copyright_author_href:
copyright_url:
copyright_info:
mathjax:
katex:
aplayer:
highlight_shrink:
aside:
abcjs:
---

# Challenge-Sigaction实验报告

## 一、任务背景——sigaction简介

`sigaction`是Unix与类Unix操作系统中进程间或者内核与进程间的一种**异步通信**，用来提醒一个进程某一信号已经发生。

------

当一个信号被发送给一个进程时, 内核会中断进程的正常控制流，转而**执行与该信号相关的用户态处理函数**进行处理，在执行该处理函数前，会将该信号所设置的信号屏蔽集加入到进程的信号屏蔽集中，在执行完该用户态处理函数后，又会将恢复原来的信号屏蔽集;本次实验只需实现`[1,32]`普通信号，无需考虑`[33,64]`的实时信号。

## 二、实现思路

### 1. 概述

综合本次实验的指导书、讨论区助教的总结和大佬们的指点、往届学长学姐宝贵的博客，我对此次任务形成的大致思路以及编码流程如下：

- 在进程控制块中添加用于存储该进程已注册的信号、当前待处理的信号、当前屏蔽的信号集、用于实现信号重入的信号屏蔽栈、信号异常处理函数的入口的数据结构。
- 在用户态实现一系列用于处理信号集的函数，其中涉及到进程控制块数据改变的需要配合系统调用来实现，这也是此次实验初次上手比较困难的一部分。
- 仿照`tlb_mod`异常处理实现信号异常处理，完成上述系统调用的实现之后，对用户态内核态的关系和转换已经比较熟悉了，而且有参照，这部分不太难。
- 具体实现`do_signal`函数，难点在于实现指导书所要求的信号处理优先级机制，这里我反复修改了多次信号相关的数据结构（这说明一定要提前做好规划啊！不然牵一发而动全身，debug太难了）终于成功实现所需功能。
- 调整指导书要求的6个信号的发送方式和默认处理方式，这里只需要在内核中找到会导致相关信号出现的地方，添加系统调用发送信号即可。

### 2. 信号相关的数据结构

在`include/signal.h`中添加指导书给出的两个结构体定义，以及6个需要实现的信号量、`__how`的宏定义，这里不再赘述和展示。

在`include/env.h`的`Env`结构体中添加信号处理相关的属性：

```c
// challenge-sigaction

// 已经注册的信号
struct sigaction sigaction_list[33];
// 当前待处理的信号
int env_todo_sig[33];
// 当前的信号掩码（屏蔽集）
sigset_t env_sa_mask;
// 信号重入栈
sigset_t env_old_mask[33];
int env_old_mask_top;
// 信号处理函数入口
u_int env_sig_entry;
```

当然，也不能忘了在创建`env`的时候初始化这些新增的属性。

### 3. 信号处理函数的实现

#### 不需要使用系统调用，仅在用户态执行的

由于评测不允许新建`.c`文件，而原本`libos.c`文件中只有`exit`函数，所以我将这部分信号处理函数都放在该文件中。这部分函数实现较简单，需要注意信号编号是`[1,32]`，而`uint32_t`应该是`0-31`位；以及根据讨论区同学的指点，要注意判断传入的指针是否为空。其余不再赘述。

`include/libos.c`

```c
// 清空，全置0
int sigemptyset(sigset_t *__set) {
	if (__set == NULL) {
		return -1;
	}
    __set->sig = 0;
    return 0;
}

// 填满，全置1
int sigfillset(sigset_t *__set) {
	if (__set == NULL) {
		return -1;
	}
    __set->sig = 0;
    __set->sig = ~(__set->sig);
    return 0;
}

// 添加一个信号，将某位 置1
int sigaddset(sigset_t *__set, int __signo) {
	if (__set == NULL) {
		return -1;
	}
    if (__signo > 32 || __signo < 1) {
        return -1;
    }
    __set->sig |= (1 << (__signo - 1));
    return 0;
}

// 删除一个信号，将某位 置0
int sigdelset(sigset_t *__set, int __signo) {
	if (__set == NULL) {
		return -1;
	}
    if (__signo > 32 || __signo < 1) {
        return -1;
    }
    __set->sig &= ~(1 << (__signo - 1));
    return 0;
}

// 检查信号集是否包含__signo信号
int sigismember(const sigset_t *__set, int __signo) {
	if (__set == NULL) {
		return -1;
	}
    if (__signo > 32 || __signo < 1) {
        return -1;
    }
    if (((__set->sig >> (__signo-1)) & 1) == 1) {
        return 1;
    } else {
        return 0;
    }
}

// 检查信号集是否为空
int sigisemptyset(const sigset_t *__set) {
	if (__set == NULL) {
		return -1;
	}
    if (__set->sig == 0) {
        return 1;
    } else {
        return 0;
    }
}

// 计算两个信号集的交集
int sigandset(sigset_t *__set, const sigset_t *__left, const sigset_t *__right) {
	if (__set == NULL || __left == NULL || __right == NULL) {
		return -1;
	}
    __set->sig = __left->sig & __right->sig;
    return 0;
}

// 计算两个信号集的并集
int sigorset(sigset_t *__set, const sigset_t *__left, const sigset_t *__right) {
	if (__set == NULL || __left == NULL || __right == NULL) {
		return -1;
	}
    __set->sig = __left->sig | __right->sig;
    return 0;
}
```

#### 需要使用系统调用的

即需要对内核态的数据结构进行修改的。有`sigaction`，`kill`，`sigprocmask`，`sigpending`4个，用户态的很好写，判断一下边界条件，直接调用`sycall_*`方法即可。

`user/lib/libos.c`

```c
// 信号注册函数
int sigaction(int signum, const struct sigaction *newact, struct sigaction *oldact) {
    if (signum > 32 || signum < 1) {
        return -1;
    }
    if (syscall_get_sig_act(0, signum, oldact) != 0) {
        return -1;
    }
    // 注册信号处理函数入口
    if (env_set_sig_entry() != 0) {
        return -1;
    }
    return syscall_set_sig_act(0, signum, newact);
}

// 信号发送函数
int kill(u_int envid, int sig) {
    return syscall_kill(envid, sig);
}

// 信号屏蔽函数
int sigprocmask(int __how, const sigset_t *__set, sigset_t *__oset) {
    if (__set == NULL) {
        return -1;
    }
	if (__how < 1 || __how > 3) {
		return -1;
	}
    return syscall_set_sig_set(0, __how, __set, __oset);
}

// 获取当前进程被阻塞且未处理的信号集
int sigpending(sigset_t *__set) {
    if (__set == NULL) {
        return -1;
    }
    return syscall_get_sig_pending(0, __set);
}
```

内核态具体的实现。

`kern/syscall_all.c`

```c
// 发送信号我的处理是将对应进程块的待处理信号集对应位置置1
int sys_kill(u_int envid, int sig) {
	if (sig > 32 || sig < 1) {
		return -1;
	}

	struct Env *env;
	if (envid2env(envid, &env, 0) < 0) {
		return -1;
	}
	env->env_todo_sig[sig] = 1;
	return 0;
}
// 给当前进程注册一个信号，设置sigaction结构体的两个属性即可，注意类型转换
int sys_set_sig_act(u_int envid, int signum, struct sigaction *act) {
	struct Env *env;
	if (envid2env(envid, &env, 0) < 0) {
		return -1;
	}
	if (act) {
		env->sigaction_list[signum].sa_handler = (void *)act->sa_handler;
		env->sigaction_list[signum].sa_mask = act->sa_mask;
	}
	return 0;
}
// 上面函数的逆操作，获取当前进程指定信号的sigaction结构体的两个属性
int sys_get_sig_act(u_int envid, int signum, struct sigaction *oldact) {
	struct Env *env;
	if (envid2env(envid, &env, 0) < 0) {
		return -1;
	}
	if (oldact) {
		oldact->sa_handler = (void *)env->sigaction_list[signum].sa_handler;
		[env->env_sa_mask_top];
		oldact->sa_mask = env->sigaction_list[signum].sa_mask;
	}
	return 0;
}
// 设置当前进程当前的信号屏蔽集
int sys_set_sig_set(u_int envid, int how, sigset_t *set, sigset_t *oldset) {
	struct Env *env;
	try(envid2env(envid, &env, 0));
	// 保存原来的信号掩码
	if (oldset) {
		oldset->sig = env->env_sa_mask.sig;
	}
	
	if (set) {
		// env->env_sa_mask_top++;
		if (how == SIG_BLOCK) {
			// 将set指定的信号添加到当前进程的信号掩码中
			env->env_sa_mask.sig |= set->sig;
		} else if (how == SIG_UNBLOCK) {
			// 将set指定的信号从当前进程的信号掩码中删除
			env->env_sa_mask.sig &= ~(set->sig);
		} else {
			// 将当前进程的信号掩码设置为set指定的信号
			env->env_sa_mask.sig = set->sig;
		}
	}
	return 0;
}
// 获取当前进程待处理且未被阻塞的信号，即待处理集对应位为1且屏蔽集对应位不为1，要注意特判不能被阻塞的SIGKILL
int sys_get_sig_pending(u_int envid, sigset_t *set) {
	struct Env *env;
	if (envid2env(envid, &env, 0) < 0) {
		return -1;
	}
	for (int i = 1; i <= 32; i++) {
		if ((env->env_sa_mask.sig >> (i-1)) & 1) {
			// 被阻塞就跳过，但是SIGKILL不可被阻塞
			if (i != SIGKILL) {
				continue;
			}
		}
		if (env->env_todo_sig[i]) {
			set->sig &= (1 << (i-1));
		}
	}
	return 0;
}
```

实现完整系统调用的其他必要操作不再赘述。

### 4. 信号异常处理的实现

这部分是此次操作的核心，要实现从用户态到内核态再到用户态的转变。总的来说就是

用户态发生某事件导致给某进程发送信号->某进程在某次从内核态跳回用户态的过程中进入信号异常处理，根据优先级选择一个待处理的信号进行处理->对应进程跳到用户态的信号处理函数进行处理……

这个过程不断循环，就是完整的信号处理流程：`正常控制流——发——选——处理——正常控制流`

#### 用户态的信号处理函数

负责接受内核态传来的参数，若有定义好的`sa_handler`则执行，否则按默认处理。除了默认处理是结束进程的（根据指导书要求，用用户态的`exit()`函数结束进程），最后都要进行系统调用恢复现场，也就是回到之前的内核态。

`user/lib/fork.c`

```c
// 信号异常处理函数
static void __attribute__((noreturn)) sig_entry(struct Trapframe *tf, void (*sa_handler)(int), int signum, int envid) {
	if (sa_handler != 0 && signum != SIGKILL) {
		sa_handler(signum);	//调用信号对应的处理函数
		// 恢复现场
		int r = syscall_set_sig_trapframe(0, tf);
		user_panic("sig_entry syscall_set_trapframe return %d", r);
	}
	// 没定义处理函数，进行默认处理
	if (signum == SIGINT || signum == SIGILL || signum == SIGSEGV || signum == SIGKILL) {
		// 默认停止进程
		exit();
		user_panic("sig_entry syscall_env_destory return");
	} else {
		// 默认忽略
		// 直接恢复现场
		int r = syscall_set_sig_trapframe(0, tf);
		user_panic("sig_entry syscall_set_trapframe return %d", r);
	}
} 
```

#### 恢复现场的系统调用

可以参考已有的`sys_set_trapframe`函数实现`sys_set_sig_trapframe`，实际上实现逻辑是一摸一样的，但我选择在这个用户态到内核态的过渡函数（实际上现在已经回到内核态了）里维护进程的信号掩码栈——运行到这里说明已经处理完了一个信号，要将该信号的自我屏蔽取消，为了便于实现使用栈来操作，只要在这里将栈顶指针回退一格就行。

`kern/syscall_all.c`

```c
int sys_set_sig_trapframe(u_int envid, struct Trapframe *tf) {
	if (is_illegal_va_range((u_long)tf, sizeof *tf)) {
		return -E_INVAL;
	}
	struct Env *env;
	try(envid2env(envid, &env, 1));
	// 维护信号掩码栈
	curenv->env_old_mask_top -= 1;
	curenv->env_sa_mask.sig = curenv->env_old_mask[curenv->env_old_mask_top].sig;

	if (env == curenv) {
		*((struct Trapframe *)KSTACKTOP - 1) = *tf;
		return tf->regs[2];
	} else {
		env->env_tf = *tf;
		return 0;
	}
}
```

#### 内核态的信号处理函数

这应该是实现该任务最核心的函数了，该函数位于内核态，要在这里选出要处理的信号，将相关参数传给用户态的信号处理函数，我将几乎所有与信号优先级、信号重入、`SIGKILL`的特殊处理相关的操作都放在了这里。由于对信号的操作必然涉及对内核数据的修改，因此放在内核态实现是非常理所当然的。

总体思路是：先从待处理信号集中找一个信号出来处理。讨论区讨论比较多的关于信号优先级和信号被打断等问题。其实所谓被打断和优先级是不相干的，但本质上又是同一个问题，因为该信号处理机制遵循的原则就是收到信号->到内核态处理->根据编号小的优先级高，被屏蔽的不能选两条规则选一个信号出来处理，又因为规定每个信号在被处理的过程中会屏蔽自己，所以实际上被打断的时候是无关优先级的，换句话说：只要在处理一个信号的过程中，收到另一个非同类信号，是一定会被打断的。但为什么说本质是同一个问题呢？因为代码实现的逻辑没有区别，只要遵循两条原则+一个SIGKILL特例来处理就可以了。

`kern/tlbex.c`

```c
void do_signal(struct Trapframe *tf) {
    // 如果当前待处理信号集为空，就直接返回
	int flag = 0;
	for (int i = 1; i <= 32; i++) {
		if (curenv->env_todo_sig[i] == 1) {
			flag = 1;
			break;
		}
	}
	if (flag == 0) {
		return;
	}
	// 找一个信号出来处理
	int sig_do_now = 0;
	// 对SIGKILL特殊对待，只要它在待处理信号集里，就必须去执行
	if (curenv->env_todo_sig[SIGKILL]) {
		sig_do_now = SIGKILL;
	} else {
		for (int i = 1; i <= 32; i++) {
			if ((curenv->env_sa_mask.sig >> (i-1)) & 1) {
				// 被阻塞就跳过
				continue;	
			}
			if (curenv->env_todo_sig[i]) {
				sig_do_now = i;
				break;
			}
		}
	}
	// 待处理信号集中的信号恰巧全被屏蔽了，没法处理，直接返回
	if (sig_do_now == 0) {
		return;
	}
	// 找完了，接下来要到用户态的分发函数
	// 先把当前的屏蔽集存到栈里，然后更新当前的屏蔽集，把当前要去处理的信号的屏蔽集及其自身放到当前的屏蔽集里
	if (sig_do_now != SIGKILL) {

		curenv->env_old_mask[curenv->env_old_mask_top].sig = curenv->env_sa_mask.sig;
		curenv->env_old_mask_top += 1;
		
		curenv->env_sa_mask.sig |= curenv->sigaction_list[sig_do_now].sa_mask.sig;
		curenv->env_sa_mask.sig |= (1 << (sig_do_now - 1));
	}
	// 更新完屏蔽集，可以跳转到用户态的分发函数了
    // 即将进入用户态处理函数，可以认为该信号已经被处理了，因此将其从待处理信号集中删去
    // 实际上这样不会影响信号的重入机制，如果该信号在处理过程中被打断，那么其被打断时的现场是会被打断他的那个信号保存的，可以保证继续执行
	curenv->env_todo_sig[sig_do_now] = 0;

    // 保存现场，传参，跳转到用户态处理函数
	struct Trapframe tmp_tf = *tf;
	if (tf->regs[29] < USTACKTOP || tf->regs[29] >= UXSTACKTOP) {
		tf->regs[29] = UXSTACKTOP;
	}
	tf->regs[29] -= sizeof(struct Trapframe);
	*(struct Trapframe *)tf->regs[29] = tmp_tf;

	if (curenv->env_sig_entry) {
		tf->regs[4] = tf->regs[29];
		tf->regs[29] -= sizeof(tf->regs[4]);
		tf->regs[5] = (unsigned int)
		(curenv->sigaction_list[sig_do_now].sa_handler);
		tf->regs[29] -= sizeof(tf->regs[5]);
		tf->regs[6] = sig_do_now;
		tf->regs[29] -= sizeof(tf->regs[6]);
		tf->regs[7] = curenv->env_id;
		tf->regs[29] -= sizeof(tf->regs[7]);
		
	
		tf->cp0_epc = curenv->env_sig_entry;
	} else {
		panic("sig but no user handler registered");
	}
}
```

#### 用户态和内核态的桥梁

要实现进程每次从内核态回到用户态时，进入信号处理函数`do_signal`，需要在`ret_from_exception`中添加跳转指令。

`kern/genex.S`

```xml
FEXPORT(ret_from_exception)
	move	a0, sp
    addiu   sp, sp, -8
    jal     do_signal
    nop
    addiu   sp, sp, 8

    RESTORE_ALL
    eret
```

#### 给用户态设置异常处理函数的入口

仿照`tlb_mod`的处理实现一个入口地址`sig_entry`，在`sigaction`函数中调用，但是可能存在没有注册信号就发送该信号的情况。经过讨论区同学的提醒，可以在`libos.c`中的`libmain`函数中的`main`之前，调用一次异常处理函数入口注册函数，这样就保证了被取出来的进程控制块是注册过`sig_entry`的。

`kern/syscall_all.c`

```c
int sys_set_sig_entry(u_int envid, u_int func) {
	struct Env *env;
	try(envid2env(envid, &env, 1));
	env->env_sig_entry = func;
	return 0;
}
```

#### 子进程继承父进程信号量的实现

子进程需要继承的是：父进程已经注册的信号、信号处理入口、信号屏蔽集，其余内容初始化。在内核中创建子进程的地方直接赋值即可。

`kern/syscall_all.c`

```c
int sys_exofork(void) {
	...
	//challenge-sigaction
	for (int i = 1; i <= 32; i++) {
		e->sigaction_list[i] = curenv->sigaction_list[i];

		e->env_old_mask[i].sig = 0;
		e->env_todo_sig[i] = 0;
	}
	e->env_sa_mask = curenv->env_sa_mask;
	e->env_sig_entry = curenv->env_sig_entry;

	e->env_old_mask_top = 0;
	...
}
```

#### 内核态信号发送的实现

根据指导书要求，`SIGCHLD`、`SIGILL`、`SIGSYS`、`SIGSEGV`信号是由内核发出的，这就要求我们对内核做出相应的修改。

##### `SIGSEGV`

指导书中已明确说明，需要在访问到低于`0x003fe000`的地址时取消原有的`panic`，改为发送信号。

`kern/tlbex.c`

```C
static void passive_alloc(u_int va, Pde *pgdir, u_int asid) {
	struct Page *p = NULL;

	if (va < UTEMP) {
		sys_kill(0, SIGSEGV);
		// panic("address too low");
	}
    ...
```

##### `SIGCHLD`

根据指导书描述，该信号是子进程终止信号，我的理解是子进程终止时要给父进程发送该信号，所以我找到内核态中销毁进程处，在真正销毁前给父进程发送该信号。

`kern/syscall_all.c`

```c
int sys_env_destroy(u_int envid) {
	struct Env *e;
	try(envid2env(envid, &e, 1));
	sys_kill(e->env_parent_id, SIGCHLD);

	printk("[%08x] destroying %08x\n", curenv->env_id, e->env_id);
	env_destroy(e);
	return 0;
}
```

##### `SIGILL`

根据指导书描述，该信号表示执行了非法指令，内核中原有的处理应该在`do_reserved`函数中，我取消了该函数原有的当前异常栈打印和`panic`，改为发送信号。

`kern/traps.c`

```c
void do_reserved(struct Trapframe *tf) {
    sys_kill(0, SIGILL);
	// print_tf(tf);
	// panic("Unknown ExcCode %2d", (tf->cp0_cause >> 2) & 0x1f);
}
```

##### `SIGSYS`

根据指导书定义，该信号表示系统调用号未定义，系统调用是`syscall`，显然相关的处理应该在`do_syscall`函数中，在这里我将`cp0_epc`加4以保证返回后跳过该未定义的系统调用指令，之后再发送信号。

`kern/syscall_all.c`

```c
void do_syscall(struct Trapframe *tf) {
	int (*func)(u_int, u_int, u_int, u_int, u_int);
	int sysno = tf->regs[4];
	if (sysno < 0 || sysno >= MAX_SYSNO) {
		tf->regs[2] = -E_NO_SYS;
		tf->cp0_epc += 4;
		sys_kill(0, SIGSYS);
		return;
	}
	...
```

## 三、实验难点

我认为本次实验最难的是理解用户态和内核态的关系，以及是如何进行切换的。该任务每一部分的处理都会涉及用户态和内核态的关联、切换问题；其次是信号优先级和重入机制的实现，尤其是重入机制，涉及到掩码栈的维护，用户态内核态的不断切换……我对于优先级和重入机制的理解与具体实现已经在实现思路中体现。

## 四、心得体会

完成该挑战性任务之后，我大大加深了对于操作系统内核态与用户态的理解程度，也更能理解为什么*原仓周老师*说操作系统可以理解成一个异常处理流，在此次实现的信号机制中，操作系统内核完成的任务是接收信号，挑选信号，把相应的信号发送给对应的进程去处理，而这一切在用户态都是不可见的，用户态只需要发送信号，然后就可以等着信号被处理了。

## 五、碎碎念以及鸣谢

这次挑战性任务完成的十分艰难，心路历程及过程如下：
- 五月底挑战性任务发布，走马观花地浏览了一遍，找了找学长学姐的`github`和博客，没有太多想法，遂搁置。
- 六月一直到端午假期，都没在关注挑战性任务，只是偶尔看看讨论区大伙热火朝天的讨论，尤其是`Sigaction`这题，心里有点痒痒，我又对`Shell`的题比较感兴趣，遂于端午节第一天开始写，结果以失败告终，心态一整个大崩啊。
- 端午节第二天收拾心情，果断止损，抓紧开始复习期末考试，这在后来看来是十分明智的选择。因为讨论区仍在不断迭代，到后期有了超级多有用的资源，大佬已经把石头摆好了，后来人只要摸着石头过河就行。而我在这个时间及时的复习了数据库和人工智能，进入考期后也能借着考试之间的空隙全力进攻挑战性任务。
- 考期第一周周二晚上，刚考完软工的我发现了[张杨学姐的博客](https://yanna-zy.github.io/2023/06/18/BUAA-OS-challenge/)，对去年的挑战性任务有非常详细的讲解，与今年的题面进行对比后，发现总体框架变化不是很大，于是我果断换题。
- 借助学姐的博客，又翻着自己以前`lab`的代码，我彻底搞懂了**系统调用**和**异常处理**的流程以及`MOS`中代码的体现，也对挑战性任务的整体流程有了大致把握。
- 周三一整天，我先无脑按照博客复现了一遍，评测能得25分，甚至40分（不知道是什么原因导致的某个测试点如此“灵活”）
- 然后开始魔改，中间改碎了两次，甚至用上了`git reset --hard`强制重开……还把耳机和外套全部搞丢了（幸好最后全部寻回，OS你害人不浅！）。
- 周四复习了一天人工智能。
- 周五中午考完，午觉都没睡，直接开干，到晚上基本实现了信号重入和优先级实现的框架，但是参照讨论区大佬搓的测试样例，顺序还是不对。不过已经是一些小细节上的问题了！周五晚上前脑子里想的是：看到胜利的曙光了，明天一定可以结束战斗，然后周日周一再复习复习数据库。
- 事实证明的确如此，周六7点45到达图书馆开干，12点左右终于通过了上文提到的样例，但一提交竟然只有15分，竟然搞了个编译错误。事已至此，先吃饭吧！
- 编译错误显然不会是大问题，吃完饭回来我在本地开启编译优化跑了一遍，发现了`debug`时没有注释掉的`printk`，好家伙。再一提交，55分，且是16/18和5/6。
- 逛了逛讨论区，也有和我一样差几个点通过的，但没有什么有价值的解决方案，我检查了几个信号的默认处理方式，发现我对`SIGKILL`的默认处理是在内核就完成的，那我想干脆跟其他几个统一吧，而且助教在讨论区说过要统一用`exit`来结束进程，改了一下，提交——100分拿下，此时是周六下午2点多。写写实验报告，美美去和中法和马协的兄弟们拍毕业照。
- 感谢张杨学姐的博客，对我帮助极大。所以在学习搭建个人博客时，我第一篇上传的就是挑战性任务的报告，希望也能帮助到后来的学弟学妹。