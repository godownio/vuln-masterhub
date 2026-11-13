---
id: defense-detection-xz-liblzma-backdoor-sshd-triage
title: 主机 xz/liblzma 后门排查：沿 sshd 依赖链定位库文件，版本核对 + _get_cpuid 字节签名 hexdump 初判
type: scenario
domain: defense
path: defense/detection
technique: xz-liblzma-backdoor-sshd-triage
aliases:
- xz 后门检测
- liblzma 后门排查
- CVE-2024-3094 检测
- sshd liblzma 检查
- liblzma 字节签名
- liblzma hexdump 检测
tags:
- detection
- xz
- liblzma
- sshd
- supply-chain
- backdoor
- cve-2024-3094
- hexdump
- host-triage
cve:
- CVE-2024-3094
severity: critical
confidence: high
status: verified
affected_versions: xz-utils 5.6.0 / 5.6.1
created: '2026-11-10'
updated: '2026-11-10'
verification:
  verified_by: verifier-V482
  verified_at: '2026-11-10T20:41:43+08:00'
  notes: 已对照原文与7张图核对：ldd sshd 定位 liblzma（systemd通知补丁间接依赖）、字节签名 f30f1efa...2410 与原文逐字节一致、xz -V 5.6.0/5.6.1、TERM/argv[0]/LD_DEBUG/LD_PROFILE/LANG 激活条件、env -i 复现命令、登录变慢与valgrind invalid write 线索均一致；affected_versions 按原文明确保留。与 xz CVE 技术链卡、IFUNC 通用取证卡为不同原子（主机排查 vs 攻击链/通用IFUNC），非重复；dup-scan.json(11-08)早于建卡。未验证点：检测脚本未在本机实测，静态签名可能被重编译规避（卡内已注明边界）；frontmatter无sources/source_url。
---

## 一句话结论

判断 Linux 主机是否受到 xz 后门影响，可以先做三层快速排查：`xz -V` 核对版本是否为 5.6.0/5.6.1，用 `ldd $(which sshd)` 找到 sshd 实际加载的 liblzma（OpenSSH 本身不用 lzma，是发行版 systemd 通知补丁引入的间接依赖），再对库文件做字节签名 grep（`f30f1efa554889f54c89ce5389fb81e7000000804883ec28488954241848894c2410`），即可给出“很可能受影响 / 很可能不受影响”的初判。

## 原理

- **签名来源**：后门替换了 liblzma 的 IFUNC resolver，并注入 `_get_cpuid` 函数；该函数在编译产物中保留固定的机器码前缀（`endbr64; push rbp; mov rbp,rsi; mov rsi,r9; push rbx; mov ebx,edi; and edi,0x80000000; sub rsp,0x28; mov [rsp+0x18],rdx; mov [rsp+0x10],rcx`），因此这段字节可直接当静态签名用。
- **为什么沿 sshd 查**：后门的实际利用路径在 sshd 进程内。OpenSSH 本身不直接依赖 liblzma，但 Debian 等发行版给 sshd 打了 systemd 通知补丁，使其链接 `libsystemd`，而 `libsystemd` 依赖 liblzma；`ldd` 输出反映的正是这条真实加载链。若 sshd 根本不链接 liblzma，则该主机无法通过这条链被利用（但其他加载 liblzma 的进程仍需单独排查）。
- **为什么不能只看版本**：`xz -V` 只能看版本号，不能证明库文件未被替换或不是从带毒 tarball 构建；字节签名检查针对的是实际 `liblzma.so` 文件内容。
- **行为线索**：后门激活后 SSH 登录明显变慢、登录期间 sshd CPU 占用升高；在 valgrind 下加载 liblzma 会出现 invalid write 报错——该后门正是被外部工程师在排查这些异常时发现。
- **为什么直接跑 sshd 不一定复现**：后门激活要求特定环境：`TERM` 未设置、`argv[0]` 为 `/usr/sbin/sshd`、`LD_DEBUG`/`LD_PROFILE` 未设置、`LANG` 已设置，并会检测 rr / gdb 等调试环境；在 systemd 之外启动时后门可能只被短暂调用而不触发完整行为。研究时可构造干净环境：`env -i LANG=en_US.UTF-8 /usr/sbin/sshd -D`。
- **边界**：该签名是特定版本的静态特征；攻击者重编译、改写函数序言或加壳即可规避。无命中不等于安全，需结合版本、包来源、符号表与运行时行为综合判断。

## 触发条件

- 目标为 x86-64 Linux 主机，且 liblzma 可能来自发行版仓库或第三方构建；
- 主机具有 `ldd`、`hexdump`、`grep`、`xz` 等基础工具（应急排查常在 live 系统或挂载镜像上执行）；
- 能读取 sshd 实际链接的库文件（只读镜像/容器可复制出来离线分析）。

## 利用步骤

1. `xz -V` 查看 liblzma 版本是否为 5.6.0 / 5.6.1。
2. `ldd $(which sshd) | grep liblzma` 找到 sshd 实际加载的 liblzma 路径；无输出说明 sshd 不直接依赖 liblzma，仍应检查 libsystemd 链与其他加载 liblzma 的进程。
3. 对找到的库文件做字节签名检查：`hexdump -ve '1/1 "%.2x"' <liblzma路径> | grep -q f30f1efa554889f54c89ce5389fb81e7000000804883ec28488954241848894c2410`。
4. 命中后进一步确认：用 `dpkg -S` / `rpm -qf` 查包来源与版本，用 `readelf -sW` / `nm -D` 查 IFUNC 符号与异常导出，比对发行版公告与软件包哈希。
5. 行为侧佐证：观察 SSH 登录延迟与 sshd CPU；在隔离环境中用 `env -i LANG=en_US.UTF-8 /usr/sbin/sshd -D` 复现激活条件（仅限授权分析）。
6. 确认受影响后按失陷主机处置：升级/降级并重装 liblzma，轮换主机密钥与凭据，保留镜像做取证。

## PoC

仅使用只读命令的最小检测片段（不执行样本）：

```bash
# 1) 版本初筛
xz -V

# 2) 定位 sshd 实际加载的 liblzma
path="$(ldd $(which sshd) | grep liblzma | grep -o '/[^ ]*')"

# 3) 对库文件做字节签名判定
hexdump -ve '1/1 "%.2x"' "$path" \
  | grep -q f30f1efa554889f54c89ce5389fb81e7000000804883ec28488954241848894c2410 \
  && echo probably vulnerable || echo probably not vulnerable
```

## 变体与关联

- 完整后门链路与构建注入细节见 [[code-analysis-cve-xz-liblzma-supply-chain-backdoor-ifunc-got-sshd]]；加载期 IFUNC 行为取证见 [[defense-forensics-ifunc-resolver-triage]]。
- 变体与误判：只查 `xz -V` 会漏掉“版本正确但文件被替换/第三方构建”；只看 sshd 依赖会漏掉其他加载 liblzma 的进程；签名可被重编译规避。
- 排查思路可推广为“从入口服务反查间接依赖库”：对关键 daemon 先跑 `ldd` 建立依赖清单，再对可疑基础库做版本、哈希与内容签名核对。

## 检测与防御

- **防御**：从发行版签名仓库安装，避免直接执行来源不明的 release tarball；减少 sshd 不必要的间接依赖（systemd 通知补丁）；启用包完整性与文件哈希基线。
- **检测**：把 `xz -V` + `ldd` + 字节签名检查纳入应急脚本；对 liblzma 5.6.0/5.6.1 做全盘排查；结合 SSH 登录延迟、sshd CPU 异常与 valgrind 报错等行为线索。
- **注意**：该脚本只覆盖 5.6.0/5.6.1 的已知签名，其他变体需用符号表、包来源与运行时行为分析补充。
