---
id: code-analysis-reverse-anti-debug-delayed-conditional-trigger
title: 恶意样本延迟执行与多信号条件触发：uptime/时间窗/网络/CPU/内存门控与分阶段持久化
type: scenario
domain: code-analysis
path: code-analysis/reverse/anti-debug
technique: delayed-conditional-execution-multi-signal-gating
tags:
- anti-sandbox
- evasion
- linux
- delayed-execution
- conditional-trigger
- persistence
- malware
- timing
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V175
  verified_at: '2026-11-06T11:39:53+08:00'
  notes: 已对照原文与 14 张截图核对；代码结构、阈值与沙箱 0/28 结果一致；PoC 未独立复跑，阈值/哈希为实现示例，需按样本实测。
url: /docs/code-analysis/reverse/anti-debug/code-analysis-reverse-anti-debug-delayed-conditional-trigger/
draft: false
kb_aliases:
- 延迟执行
- 条件触发
- uptime 门控
- 网络可达性检测
- 分阶段持久化
- 沙箱超时绕过
---

## 一句话结论

样本启动后不立即执行恶意行为，而是先随机延迟，再按系统 `uptime`、目标时段、外网可达性、用户活动、CPU 负载、可用内存等多信号打分，达到阈值才继续；持久化和 C2 通信也拆成 5 秒/2 分钟/5 分钟/30 分钟等不同延迟分阶段执行。这样恶意动作可能完全落在沙箱的固定分析窗口之外，或被打散到无法与初始样本关联的时间点。

## 原理

- **uptime 门控**：读 `/proc/uptime`，要求系统已运行超过随机阈值（示例 60–3660 秒）。真实主机通常已运行数小时/数天；刚启动的沙箱、一次性容器 uptime 很短，直接不满足。
- **时间窗门控**：`localtime` 后要求当前小时落在随机目标小时 ±1 内（示例目标凌晨 2 点）。自动化分析多在白天进行，夜间触发可避开分析排期；随机化目标小时避免固定特征。
- **网络可达性**：`ping -c 1` 8.8.8.8、1.1.1.1、www.google.com，要求至少 2 个可达。隔离沙箱通常无外网或只放行特定域名，真实受害主机一般可出网。
- **用户活动**：`who | grep -q "pts\|tty"` 判断是否有交互登录；沙箱/服务器通常没有真实用户会话。
- **资源与负载**：从 `/proc/stat` 计算 CPU 使用率，要求 <30%；从 `/proc/meminfo` 读 `MemAvailable`，要求 >512MB。低配沙箱容易不满足。
- **多信号投票**：6 项检查中满足至少 75%（4 项）才执行，避免单一指标误判或单点被伪造。
- **延迟与调度**：初始化后先随机睡眠 10–59 秒；条件监控线程每 30–300 秒检查一次；恶意动作通过延迟队列分阶段执行（基础 cron 5 秒、systemd 2 分钟、`~/.bashrc` 5 分钟、数据收集 30 秒、C2 心跳 30 分钟）。
- **为什么有效**：沙箱通常只运行几分钟、无真实用户/外网、uptime 短；条件不满足时样本处于“等待”状态，没有恶意行为可供检测。即使条件满足，分阶段执行也拉长了行为链，使“样本启动→持久化→外联”不再连续出现。
- **代价与弱点**：等待条件会降低实际感染成功率；防守方如果长时间运行、模拟用户/网络并观察定时器/文件写入，仍可捕获。

## 触发条件

- 样本需要在受害主机上长期驻留，且能接受延迟上线。
- 沙箱/分析环境具有短 uptime、无外网、无交互用户、资源受限等特征。
- 样本能够读取 `/proc`、执行 `ping`/`who`，或通过系统 API 获取等价信息。
- 攻击者愿意用“可能不触发”换取“分析环境不触发”。

## 利用步骤

1. 启动后先 `sleep` 随机 10–59 秒，避开样本提交后的即时分析窗口。
2. 读取 `/proc/uptime`，与随机阈值比较；读取 `localtime`，判断是否在目标小时 ±1 内。
3. 用 `ping`/DNS/HTTP 探测多个公网目标，统计可达数量；用 `who` 判断交互会话。
4. 读取 `/proc/stat` 与 `/proc/meminfo`，计算 CPU 使用率和可用内存。
5. 汇总 6 项检查，达到 4 项才置位执行标志；否则进入 30–300 秒的循环重试。
6. 条件满足后，把持久化/收集/C2 动作加入延迟队列，按不同时间间隔分阶段执行，避免连续行为链。
7. 每个动作执行前可再次检查条件；失败则重新调度，保持长期静默。

## PoC

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

static int check_uptime(void) {
    FILE *f = fopen("/proc/uptime", "r");
    double up = 0;
    if (f) { fscanf(f, "%lf", &up); fclose(f); }
    return up > 300;                     /* 示例阈值 */
}

static int check_hour(void) {
    time_t t = time(NULL);
    struct tm *tm = localtime(&t);
    return tm && tm->tm_hour >= 1 && tm->tm_hour <= 3;  /* 示例目标时段 */
}

static int check_net(void) {
    int ok = 0;
    ok += system("ping -c 1 -W 1 8.8.8.8 >/dev/null 2>&1") == 0;
    ok += system("ping -c 1 -W 1 1.1.1.1 >/dev/null 2>&1") == 0;
    ok += system("ping -c 1 -W 1 www.google.com >/dev/null 2>&1") == 0;
    return ok >= 2;
}

static int check_user(void) {
    return system("who | grep -q \"pts\\|tty\"") == 0;
}

static int check_cpu(void) {
    FILE *f = fopen("/proc/stat", "r");
    unsigned long u, n, s, i;
    if (!f) return 0;
    fscanf(f, "cpu %lu %lu %lu %lu", &u, &n, &s, &i);
    fclose(f);
    unsigned long total = u + n + s + i, used = total - i;
    return total && (used * 100.0 / total) < 30.0;
}

static int check_mem(void) {
    FILE *f = fopen("/proc/meminfo", "r");
    char line[256];
    unsigned long avail = 0;
    if (!f) return 0;
    while (fgets(line, sizeof(line), f))
        if (sscanf(line, "MemAvailable: %lu kB", &avail) == 1) break;
    fclose(f);
    return avail > 512 * 1024;
}

int main(void) {
    int score = check_uptime() + check_hour() + check_net()
              + check_user() + check_cpu() + check_mem();
    if (score < 4) return 0;             /* 未满足：静默退出或继续等待 */
    /* 满足后分阶段执行持久化/收集/C2，示例省略 */
    return 0;
}
```

说明：阈值为文章示例的经验值，实际样本会随机化并可能用等价 syscall/API 替代 `ping`/`who`；`system()` 调用本身是明显行为特征，隐蔽实现会直接走 socket/`/proc` 解析。PoC 只演示判定逻辑，不包含恶意动作。

## 变体与关联

- **Windows 对应物**：`GetTickCount64`/`QueryUnbiasedInterruptTime` 判断 uptime，`InternetGetConnectedState`/`WinInet` 判断网络，`GetLastInputInfo` 判断用户活动，`GlobalMemoryStatusEx` 判断内存；本库 `code-analysis-reverse-anti-debug-sandbox-environment-checks` 覆盖部分 Windows 环境检查。
- **信号/定时器触发**：`SIGUSR1` 激活、`timerfd`/`SetWaitableTimer`、计划任务延时启动；本库 `pentest-c2-signal-activated-dormant-implant` 是信号触发版本。
- **C2 侧**：心跳加随机抖动（jitter）、长时间休眠、按时间窗轮询，减少固定 beacon 周期特征。
- **失败点**：沙箱可能伪造 uptime/资源/网络，或长时间运行并模拟用户；等待过久也会导致真实用户重启/关机而失效。

## 检测与防御

- **检测**：监控进程长时间 `sleep`/`nanosleep`/定时器、反复读取 `/proc/uptime`、`/proc/stat`、`/proc/meminfo`、执行 `ping`/`who`；监控延迟出现的 cron/systemd/`~/.bashrc` 修改和周期性外联。
- **沙箱增强**：提供较长 uptime、可出网环境、模拟鼠标/键盘活动和交互会话；把分析窗口拉长到小时级，并在样本退出后继续观察文件/网络变化。
- **关联分析**：把“样本启动→延迟→写持久化→外联”按时间线关联，而不是只看启动后几秒的行为；对短命进程的父进程/子进程链做追踪。
- **防御**：限制未知样本执行；对 cron/systemd/用户启动项的变更做完整性监控；对异常长时间休眠后突然活跃的进程告警。
