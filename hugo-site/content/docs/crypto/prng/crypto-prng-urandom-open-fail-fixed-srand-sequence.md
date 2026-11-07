---
id: crypto-prng-urandom-open-fail-fixed-srand-sequence
title: /dev/urandom 打开或读取失败导致 srand 种子退化为固定序列
type: scenario
domain: crypto
path: crypto/prng
technique: urandom-fail-srand-degradation
tags:
- prng
- srand
- urandom
- glibc
- ctf
- predictable
- uninitialized
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V95
  verified_at: '2026-11-05T20:03:39+08:00'
  notes: 已对照原文 pwner_LEVEL1 与 14 张图核对：main 中 open("/dev/urandom")+read(fd,buf,4) 不检查返回值，失败时 buf 为 0，srand(buf[0]) 退化为固定种子；文中明确远程部署未修，导致每次启动随机数字序列相同；符号偏移按首轮已知关系反推的利用方式与原文 exp 一致。未验证点：未在容器/远程复现 open 失败；卡片为通用 PRNG 退化场景，PoC 未本机复跑；无组件版本。
url: /docs/crypto/prng/crypto-prng-urandom-open-fail-fixed-srand-sequence/
draft: false
kb_aliases:
- urandom 失败
- 随机源退化
- 固定随机序列
- srand(0)
- rand 序列复现
---

## 一句话结论

程序若把 `open("/dev/urandom")` + `read` 的结果直接作为 `srand()` 种子却不检查返回值，一旦 open/read 失败（容器缺少设备、权限不足、fd 耗尽），种子就来自未初始化且通常为 0 的栈变量；此后每次启动的 `rand()` 序列完全相同，攻击者可离线复现全部“随机”数字、符号或验证答案。

## 原理

- `/dev/urandom` 是内核 CSPRNG 接口，正常读取能得到不可预测字节；但这依赖 open/read 成功。
- 典型缺陷代码：`int fd = open("/dev/urandom", 0); read(fd, buf, 4); seed = buf[0]; srand(seed);`。若 `open` 返回 -1，`read(-1, ...)` 直接失败且不会写入 `buf`，程序也没有检查返回值。
- `buf` 是栈上未初始化数组。在新进程/稳定的栈布局下其内容往往是 0（或某个固定残留值），于是 `srand(0)`/固定种子；glibc `rand()` 是确定性 PRNG，同一种子必然产生同一序列。
- 只要验证逻辑（算术题、验证码、洗牌、令牌）完全由 `rand()` 派生，攻击者用相同 glibc 的 `srand/rand` 就能预计算每个输出；即使程序把“真实符号”和“显示符号”做了偏移，也可通过前几轮已知/可推导的关系还原偏移，再套用到后续轮次。
- 与 `srand(time(NULL))` 的时间种子不同，这里的根因是“随机源获取失败但未 fail-closed”，种子固定且不随时间变化，重放窗口更长。

## 触发条件

- 二进制用 `/dev/urandom`/`getrandom` 等作为种子，但没有检查 open/read 返回值或失败后继续使用未初始化缓冲区。
- 运行环境使随机源不可用：容器未挂载 `/dev`、设备节点缺失或权限不足、fd 耗尽、seccomp 拦截等。
- 验证/生成逻辑只依赖 `rand()` 序列，且使用与攻击机兼容的 libc（同版本 glibc 最佳）。
- 攻击者能观察到至少一次输出用于确认种子/序列（或直接假设种子为 0 尝试）。
- 进程每次启动的栈初始内容稳定，使得失败时的种子值可重复。

## 利用步骤

1. 逆向目标，定位 `open("/dev/urandom")`、`read`、`srand`/`rand` 调用，确认是否检查返回值、缓冲区是否初始化。
2. 判断环境是否会让 open/read 失败；在本地构造同样条件（如去掉 /dev/urandom 或传入无效 fd）验证序列是否固定。
3. 在攻击机上用 `ctypes.CDLL("libc.so.6")` 调用同版本 glibc 的 `srand(0)`（或猜测的固定种子），生成与目标一致的 `rand()` 序列。
4. 用已知的前几轮输出校验序列；若程序对符号做了 `sym[offset + rand()%6]` 之类的偏移，先用一轮可推导关系求出 offset，再复用于后续。
5. 预计算全部答案/令牌并按协议发送；对多轮验证可写循环自动交互。

## PoC

```python
import ctypes

libc = ctypes.CDLL("libc.so.6")
libc.srand(ctypes.c_uint(0))          # 随机源失败后的固定种子

def rand():
    return libc.rand()

# 目标: 每轮数字由 rand() 派生，符号由 rand()%6 选偏移
# 这里先打印前 10 个 rand()%6，用于和程序输出比对
print([rand() % 6 for _ in range(10)])
```

```c
/* 缺陷模式 */
int fd = open("/dev/urandom", 0);   /* 失败返回 -1，未检查 */
unsigned int buf[1];
read(fd, buf, 4);                   /* 失败时不写 buf */
srand(buf[0]);                      /* 种子来自未初始化栈值 */
```

## 变体与关联

- 变体：`srand(time(NULL))` 时间种子；`srand(getpid())`；`srand(未初始化变量)`；`getrandom` 失败后继续。
- 变体：`fork()` 后父子进程共享同一 PRNG 状态，子进程不重新播种即可预测。
- 变体：随机符号采用“显示符号 = 真实符号偏移”的映射，用一轮已知关系求 offset 后批量预测（本卡 PoC 的 `%6` 示例即为此类）。
- 关联：[[crypto-prng-srand-time-seed-2fa-code-prediction]]（时间种子预测）、[[crypto-prng-mt19937-clock-seed-wallet-key-recovery]]（MT19937 种子恢复）。

## 检测与防御

- 检测：审计 `open("/dev/urandom")`/`getrandom` 的返回值是否检查；在容器中确认 `/dev/urandom` 可访问；对固定种子导致的重复序列做统计检测。
- 修复：所有随机源调用必须检查返回值，失败时拒绝启动/拒绝生成令牌，不能继续使用未初始化缓冲区。
- 加固：安全场景使用 `getrandom(2)` 或 `arc4random`/CSPRNG，不使用 `rand()`；容器确保 `/dev/urandom` 可用；对验证码/令牌加入一次性随机盐与服务端绑定。
