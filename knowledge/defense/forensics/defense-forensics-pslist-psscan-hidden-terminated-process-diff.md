---
id: defense-forensics-pslist-psscan-hidden-terminated-process-diff
title: pslist 与 psscan 双视角对比：从内存镜像发现隐藏与已退出进程
type: scenario
domain: defense
path: defense/forensics
technique: pslist-psscan-hidden-terminated-process-diff
aliases:
- Volatility3 隐藏进程排查
- psscan 已退出进程
- EPROCESS 池扫描
- 进程列表差异分析
- DKOM 隐藏进程
tags:
- windows
- forensics
- memory
- volatility3
- pslist
- psscan
- process-hiding
- incident-response
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V422
  verified_at: '2026-11-09T16:56:47+08:00'
  notes: 已对照原文与14张图片核对：pslist/pstree/psscan 输出、已退出 svchost/setup.exe 的 ExitTime 示例、PID 3520 malfind RWX+MZ 均有截图佐证；差集脚本未实际运行。dedup self 排除后 top 候选为 netscan→malfind 与 Vol2 四查卡，非同一利用链。原文无受影响版本。
---

## 一句话结论

对同一份 Windows 内存镜像分别运行 `windows.pslist` 与 `windows.psscan`：pslist 沿活动进程链表枚举，psscan 直接扫描物理内存池中的 EPROCESS 对象，两者 PID 集合的差集里“仅 psscan 可见”的条目往往是已终止但结构未被覆盖、或被 DKOM 从活动链表摘除的隐藏进程；带 `ExitTime` 的条目还能还原安装器、加载器等一次性进程的执行痕迹。

## 原理

- Windows 内核用 EPROCESS 结构描述进程，活动进程通过 `PsActiveProcessHead` 双向链表串起来。`windows.pslist` 遍历这条链表，因此只能看到“此刻仍挂在链上”的进程。
- 进程退出后，EPROCESS 结构可能仍残留在内核内存池中，直到池内存被重新分配覆盖；若攻击者用 DKOM 把 EPROCESS 从活动链表 unlink，进程仍在运行、内存仍有效，但 pslist 会漏掉它。
- `windows.psscan` 不依赖链表，而是按内核池的分配特征扫描物理内存，逐个校验候选结构的字段自洽性（PID/PPID、`ImageFileName`、令牌指针、创建时间等），因此能枚举到已退出或隐藏的 EPROCESS；输出中的 `ExitTime` 非 N/A 基本可判定为已退出进程。
- 差集为什么有意义：psscan 独有且 ExitTime 为空 → 疑似隐藏进程（rootkit/DKOM）；psscan 独有且 ExitTime 有值 → 已退出进程，可用于还原一次性执行的 loader/安装器/脚本宿主；两者都有但路径或时间异常 → 交给 cmdline/pstree/netscan 交叉。
- 误报来源：池中的历史残留、PID 复用、结构被部分覆盖都会造成 psscan 噪声，必须结合时间线与其他插件确认。

## 触发条件

- 已获取 Windows 内存镜像（raw/dmp），Volatility3 与匹配的内核符号可用。
- 怀疑存在 rootkit 进程隐藏，或需要还原已退出的一次性进程（安装器、加载器、命令解释器）。
- 采集时间点附近的结构尚未被大量池分配覆盖，残留 EPROCESS 仍可解析。

## 利用步骤

1. `windows.info` 确认内核版本与符号加载是否正常。
2. 分别导出 `windows.pslist` 与 `windows.psscan` 的 PID、PPID、ImageFileName、CreateTime、ExitTime。
3. 做集合对比：以 psscan 为基准，找出不在 pslist 中的 PID，作为第一优先级。
4. 对差集按 ExitTime 分类：有退出时间 → 已退出进程，按创建/退出时间排序；无退出时间且不在 pslist → 疑似隐藏/链表损坏，需重点核实。
5. 对可疑 PID 继续跑 `windows.cmdline`、`windows.dlllist`、`windows.handles`、`windows.vadinfo`、`windows.malfind`；已退出进程因插件只按活动链表工作，需要回到 psscan 输出的物理偏移做池/字符串分析。
6. 与 `windows.pstree` 的父子关系、`windows.netscan` 的连接时间、注册表/事件日志交叉，确认恶意性并串时间线。
7. 固化命令输出、镜像哈希与工具版本。

## PoC

```bash
python vol.py -f image.raw windows.info
python vol.py -f image.raw windows.pslist  > pslist.txt
python vol.py -f image.raw windows.psscan  > psscan.txt
python vol.py -f image.raw windows.pstree
```

差集对比：

```python
import re

def pids(path):
    out = set()
    for line in open(path, encoding="utf-8", errors="ignore"):
        m = re.match(r"\s*(\d+)\s+\d+\s+\S+", line)
        if m:
            out.add(int(m.group(1)))
    return out

ps = pids("pslist.txt")
scan = pids("psscan.txt")
print("psscan-only:", sorted(scan - ps))
```

示例镜像的 psscan 输出中可见已退出的 `svchost.exe`（ExitTime 2024-01-20 19:16:22 等）与 `setup.exe`（ExitTime 2024-01-21 09:31:21），说明安装/加载类一次性进程可通过池残留还原。

## 变体与关联

- Volatility2 对应 `pslist`/`psscan`（`psscan --physical` 可看物理地址）；思路相同。
- 隐藏进程也可从 `windows.pstree` 的断链、`windows.callbacks` 的异常回调、驱动/服务列表交叉发现。
- 关联：[[defense-forensics-volatility2-cmdline-hashdump-netscan-triage]]（cmdline 识破伪装进程、psscan/malfind 作为变体）、[[defense-forensics-memory-netscan-malfind-dump-injected-process]]（netscan 反查 PID 后 malfind dump）、[[code-analysis-reverse-windows-rootkit-ssdt-zwenumeratekey-hide-service]]（内核隐藏/钩子手法）。

## 检测与防御

- 终端侧监控内核对象直接操作、可疑驱动加载与跨进程线程创建；启用 HVCI/内核保护，减少 DKOM 类 rootkit 的生存空间。
- 进程审计（4688/4689）与 EDR 遥测可作为内存差集的旁证：内存里“已退出”的进程往往在日志里留有创建/退出记录。
- 取证时先拍内存后重启，避免池残留被覆盖；对比结果必须人工排除 PID 复用与池噪声，不能仅凭 psscan 独有就定性。
