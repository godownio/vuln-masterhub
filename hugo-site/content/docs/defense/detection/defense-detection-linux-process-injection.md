---
id: defense-detection-linux-process-injection
title: Linux 进程注入检测与取证：匿名 RWX、TracerPid、auditd 与 Volatility3
type: scenario
domain: defense
path: defense/detection
technique: linux-process-injection-detection
tags:
- linux
- detection
- process-injection
- ptrace
- rwx
- auditd
- volatility
- forensics
- threat-hunting
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V91
  verified_at: '2026-11-05T20:05:42+08:00'
  notes: 已对照原文与图16/17核对：detector.py 匿名 rwxp + TracerPid!=0 + 白名单 libv8/libjvm/libmono/libLLVM；原文实测 blue-man-applet/applet.py/qterminal 等 4096/65536 字节匿名 RWX 误报，卡内已强调白名单/基线；auditd 规则 ptrace/process_vm_readv/writev/mmap a2&0x4、LiME+Volatility3 linux.proc.Maps/linux.elfs.Elfs 均与原文一致。原文无组件版本区间，未设 affected_versions；frontmatter无sources/source_url。
url: /docs/defense/detection/defense-detection-linux-process-injection/
draft: false
kb_aliases:
- Linux 进程注入检测
- 匿名 RWX 检测
- TracerPid 监控
- ptrace 审计
- /proc/mem 写入检测
- LiME Volatility3 注入取证
- 进程注入内存取证
---

## 一句话结论

Linux 进程注入虽然可以不落盘、不调用 ptrace，但仍会在内核可见面留下痕迹：匿名 `rwxp` 映射、attach 期间非 0 的 `TracerPid`、`.text`/GOT 与磁盘 ELF 不一致、`/proc/<pid>/mem` 或 `process_vm_writev` 写入、`mmap(PROT_EXEC)` 事件；实时检测用 `/proc` 扫描 + auditd/eBPF，事后取证用 LiME 抓物理内存 + Volatility3 的 `linux.proc.Maps`/`linux.elfs.Elfs`；同时要把 JIT/Electron 等合法 RWX 进程加入白名单，避免误报。

## 原理

- **匿名 RWX 映射**：远程 `mmap(PROT_READ|PROT_WRITE|PROT_EXEC)` 注入会在目标进程留下一个匿名 `rwxp` 区域；正常应用极少有 RWX 匿名映射（JIT 如 V8、JVM、LLVM、Mono 是例外）。`grep rwxp /proc/*/maps` 是快速高置信度信号，但原文实测中 `blue-man-applet`、`applet.py`/qterminal 等合法进程也会出现 4096/65536 字节的匿名 RWX，需要白名单/基线。
- **TracerPid**：`PTRACE_ATTACH` 期间目标 `/proc/<pid>/status` 的 `TracerPid` 显示 tracer PID；detach 后回到 0。attach-detach 窗口可能很短，轮询可能错过，需要事件驱动（auditd/eBPF）而不是只靠快照。
- **代码完整性**：`PTRACE_POKETEXT` 覆盖 `.text` 后，内存代码段 hash 与磁盘 ELF 不一致；GOT 劫持会把 GOT 表项指向堆/匿名映射而非 libc/合法共享库。可用 `/proc/<pid>/maps` + ELF 解析、内存 dump 对比、Volatility 检查。
- **auditd**：可记录 `ptrace`、`process_vm_readv`/`process_vm_writev`、`mmap`（带 `PROT_EXEC` 标志）等系统调用；规则需提前部署，短命注入也能留痕。
- **eBPF**：在 `sys_enter_ptrace`、`sys_enter_mmap`、`vfs_write`（过滤 `/proc/*/mem`）等 tracepoint/kprobe 上做事件关联（例如 A 在 5 秒内 ptrace B 又写 `/proc/B/mem`），比轮询更可靠；Falco/Tracee/Tetragon 已实践该方向。
- **内存取证**：LiME 抓取物理内存为 `mem.lime`；Volatility3 `linux.proc.Maps` 列出进程映射并过滤 rwx，`linux.elfs.Elfs` 对比已加载 ELF 与磁盘文件，`--dump --address` 导出可疑区域后用 objdump 反汇编。关键异常：匿名 RWX、`.text` hash 不一致、GOT 指向堆/匿名区、TracerPid 历史非 0。
- **攻击者反取证**：payload 执行后远程 `mprotect` 把 RWX 降为 RX、使用已有 RX 段、缩短 attach 窗口、`munmap`/零覆写清理；因此快照扫描不够，必须依赖 auditd/eBPF 的事件日志与内存取证。

## 触发条件

- 具备 root/`CAP_SYS_PTRACE` 或同 UID 的检测权限；能读取 `/proc/*/maps`、`status`、`mem`。
- auditd 已安装并启用；eBPF 工具需要内核 BTF/权限；Volatility3 需要 LiME 内存镜像与匹配的符号表。
- 目标进程未隐藏 `/proc`（hidepid 会影响可见性）；容器内需要宿主机视角或相应 capability。
- 需要维护合法 RWX 白名单（JIT/浏览器/Java/Electron 等），否则误报较多。

## 利用步骤

1. **快照扫描**：遍历 `/proc/[0-9]*/maps`，找 `rwxp` 且 inode=0/匿名的映射；结合 `comm`、`cmdline`、`exe` 和路径白名单过滤 JIT/图形/终端等合法进程。
2. **TracerPid 检查**：读 `/proc/<pid>/status` 的 `TracerPid`，非 0 即存在 ptrace 附加；持续监控（`--watch`）或事件驱动。
3. **代码/GOT 完整性**：解析目标 ELF 的 `.text` hash 与内存页对比；解析 GOT，检查 `puts/printf/free` 等表项是否指向 libc/合法共享库范围，而非堆/匿名映射。
4. **auditd**：部署规则监控 `ptrace`、`process_vm_readv/writev`、`mmap` 的 PROT_EXEC；用 `ausearch -k process_injection` 检索；规则写入 `/etc/audit/rules.d/` 持久化。
5. **eBPF（可选）**：用 bpftrace/Falco/Tracee 监控 `sys_enter_ptrace`、`sys_enter_mmap`、`vfs_write` 对 `/proc/*/mem` 的写，做跨事件关联；比轮询更适合短窗口。
6. **内存取证**：LiME 加载内核模块抓 `mem.lime`；Volatility3 运行 `linux.proc.Maps | grep rwx`、`linux.elfs.Elfs --pid`、dump 可疑地址并 objdump 反汇编。
7. **加固**：YAMA `ptrace_scope` 设为 1（最好 2），持久化到 `/etc/sysctl.d/99-ptrace.conf`；限制 `CAP_SYS_PTRACE`；Full RELRO；SELinux/AppArmor 阻止匿名可执行映射；容器禁用 ptrace。
8. **响应**：发现注入后保留 maps/mem/内存镜像/audit 日志，检查 payload、C2、持久化与横向；在取证完成前不要直接 kill（可能丢失内存证据）。

## PoC

```python
#!/usr/bin/env python3
# detector.py（简化版）：匿名 RWX + TracerPid
import os, re
from pathlib import Path

RWX_WHITELIST = ("libv8", "libjvm", "libmono", "libLLVM")

def comm(pid):
    try: return Path(f"/proc/{pid}/comm").read_text().strip()
    except Exception: return "unknown"

def check_tracer(pid):
    try:
        m = re.search(r"TracerPid:\s+(\d+)", Path(f"/proc/{pid}/status").read_text())
        if m and int(m.group(1)) != 0:
            print(f"[HIGH] pid={pid} ({comm(pid)}) TracerPid={m.group(1)}")
    except Exception:
        pass

def check_rwx(pid):
    try:
        for line in Path(f"/proc/{pid}/maps").read_text().splitlines():
            if "rwxp" not in line:
                continue
            parts = line.split()
            path = parts[-1] if len(parts) > 5 else ""
            inode = parts[4] if len(parts) > 4 else "0"
            if any(w in path for w in RWX_WHITELIST):
                continue
            if inode == "0" and not path.startswith("["):
                print(f"[HIGH] pid={pid} ({comm(pid)}) anon RWX {parts[0]} {path}")
            elif path:
                print(f"[MED]  pid={pid} ({comm(pid)}) file RWX {parts[0]} {path}")
    except Exception:
        pass

for entry in os.listdir("/proc"):
    if entry.isdigit() and int(entry) != os.getpid():
        check_tracer(int(entry))
        check_rwx(int(entry))
```

```bash
# auditd 规则：/etc/audit/rules.d/injection-detect.rules
-a always,exit -F arch=b64 -S ptrace -k process_injection
-a always,exit -F arch=b64 -S process_vm_readv -k process_injection
-a always,exit -F arch=b64 -S process_vm_writev -k process_injection
-a always,exit -F arch=b64 -S mmap -F a2&0x4 -k exec_mmap
# sudo auditctl -R /etc/audit/rules.d/injection-detect.rules
# sudo ausearch -k process_injection --start recent
```

```bash
# LiME + Volatility3 内存取证
sudo insmod lime-$(uname -r).ko "path=/tmp/mem.lime format=lime"
python3 vol.py -f mem.lime linux.proc.Maps | grep 'rwx' | grep -v '/usr/lib'
python3 vol.py -f mem.lime linux.elfs.Elfs --pid 42001
python3 vol.py -f mem.lime linux.proc.Maps --pid 42001 --dump --address 0x7f3a2be00000
objdump -D -b binary -m i386:x86-64 pid.42001.0x7f3a2be00000.dmp
```

## 变体与关联

- **变体：memfd 无文件进程**：检测 `/proc/<pid>/exe` 的 `/memfd:`、maps 的 `00:01`；见 [[defense-detection-linux-memfd-fileless-process]]。
- **变体：eBPF/Falco/Tracee/Tetragon**：事件驱动监控 ptrace/mmap/proc-mem 写入，解决快照窗口问题；适合生产环境。
- **变体：GOT/代码完整性**：用 `readelf`/符号表解析 GOT，定期对比内存与磁盘；Full RELRO 降低 GOT 劫持面。
- **变体：内存取证**：LiME/Volatility3 也可用于 core dump/进程内存镜像；结合 [[defense-forensics-core-dump-secret-extraction]] 的思路提取注入 payload/密钥。
- **关联卡片**：[[pentest-c2-linux-ptrace-poketext-shellcode-injection]]、[[pentest-c2-linux-proc-mem-got-hijack]]、[[pentest-c2-linux-remote-mmap-syscall-injection]]（三种被检测的注入技术）。
- **边界**：JIT/Electron/Java 等合法进程会产生 RWX 误报；hidepid/容器命名空间影响 `/proc` 可见性；auditd 高负载可能丢事件；Volatility 需要匹配内核符号；攻击者 mprotect 降级/munmap 可规避快照。

## 检测与防御

- **检测**：`/proc` 匿名 RWX + TracerPid 轮询；auditd `ptrace`/`process_vm_*`/`mmap PROT_EXEC`；eBPF 事件关联；内存取证对比 `.text`/GOT。
- **基线**：记录正常业务的 RWX 白名单（浏览器/JIT/Java/Electron/终端），按 comm+路径+大小+时间建立基线；对新增/短命 RWX 告警。
- **加固**：YAMA `ptrace_scope=1/2` 持久化；限制 `CAP_SYS_PTRACE`；Full RELRO；SELinux/AppArmor 禁止匿名可执行映射；容器禁用 ptrace；最小化同 UID 敏感进程。
- **响应**：保存 `/proc/<pid>/{maps,status,mem,exe,comm,cmdline}`、audit 日志、PCAP、内存镜像；分析注入 payload/C2/持久化；轮换可能泄露的凭据；修复后复测检测规则。
