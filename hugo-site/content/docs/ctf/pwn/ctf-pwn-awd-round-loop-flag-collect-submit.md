---
id: ctf-pwn-awd-round-loop-flag-collect-submit
title: AWD 轮次循环编排：bash 并发计数打靶 + flags 收集归档 + 批量提交计分接口
type: scenario
domain: ctf
path: ctf/pwn
technique: awd-round-loop-flag-collect-submit
tags:
- ctf
- awd
- pwn
- automation
- bash
- threading
- flag-submit
- exploit-runner
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-W3
  verified_at: '2026-11-08T12:46:28+08:00'
  notes: 已对照原文核对：attack.sh 的 jobs 并发计数+wait、timeout --foreground、cat flags >> all_flags 再 rm flags、round_wait_time=30/wait_submit_time=5、submit_flag.py 逐行读 flags 每行起线程并用 flag[:-1] 去换行均与原文一致；已把原文并未使用的线程池表述改为逐行起线程。未验证点：未在赛事环境复跑，提交接口与 token 属赛事相关参数。
url: /docs/ctf/pwn/ctf-pwn-awd-round-loop-flag-collect-submit/
draft: false
kb_aliases:
- AWD 批量拿分
- attack.sh 轮次循环
- flag 自动提交
- submit_flag.py
- 轮次打靶脚本
- AWD 并发上限控制
---

## 一句话结论

AWD 拿分可以拆成“目标列表 → 每轮并发打靶 → 把脚本写出的 flag 追加归档 → 批量提交计分接口 → 等半轮再打”的固定循环：bash 用后台作业计数限制并发、`timeout --foreground` 限制单目标耗时，Python 用线程池把 flags 文件逐行提交，轮次间清空当轮 flags 并归档到总表，保证漏提交/重提交都可控。

## 原理

- **目标列表由探测生成**：`init_hosts.py` 按赛事给定的固定 URL 模板（形如 `http-<ip 段序号>` 的子域）并发探测，HTTP 200 视为存活并写入 `hosts`，其余写入另一个失败列表；端口（题目的 pwn 端口）在写文件时一并拼成 `host:port`，直接供 exp 使用。
- **每轮独立打靶、显式超时**：`attack.sh` 一轮里 `for line in $(cat hosts)` 逐个起后台 `timeout --foreground <run_time> python3 ./exp.py "$line" &`，`run_time` 保证卡住的利用不会拖垮整轮；起完一个 `sleep next_attack_time` 控制节奏。
- **并发上限用作业计数而不是线程池**：`((jobs++))` 累加，达到 `max_concurrent_attacks` 就 `wait` 并清零，等于用 bash 作业表做“滑动窗口”限流，避免一次性把几百个 exp 全推出去把本机/靶机压死。
- **flag 收集靠文件而不是返回值**：exp 把命中结果追加写 `flags`；进入下一轮前 `cat flags >> all_flags; rm flags`，既保留历史归档又保证本轮提交的是新 flag，避免重复提交与遗漏。
- **提交解耦**：`submit_flag.py` 读 `flags` 逐行起线程提交（示例用 `os.system` 调 `curl -X POST ... -d '{"flag": "..."}'`，也可换 requests）；`flag[:-1]` 用于去掉读取时的换行。提交接口与 token 是赛事相关参数，脚本里集中配置。
- **轮次间隔**：`round_wait_time` 设为半轮时间，让下一轮在 flag 更新后再打；`wait_submit_time` 在打完后留一点时间让 exp 写完 flags 再提交。
- **判分故障隔离**：单目标 exp 崩溃/超时只影响自己的 `timeout` 进程，失败目标在扫描阶段已单独记录，不会中断整轮。

## 触发条件

- AWD/攻防赛有多个同构靶机，题目端口与目标 URL 模板已知或可探测。
- 已有可复用的 `exp.py`，能把 flag 写到本地文件（或能返回给调度脚本）。
- 赛事提供 flag 提交接口与 token（提交格式因赛而异，需要替换脚本里的 URL/header/body）。
- 允许在比赛时限内多轮重复攻击；注意赛事规则对频率/并发的限制。

## 利用步骤

1. 改 `init_hosts.py` 的 URL 模板、端口、成功/失败输出文件名，跑一遍得到 `hosts`。
2. 改 `submit_flag.py` 的提交方式（curl 或 requests）、接口地址、认证头/token、请求体字段。
3. 调 `attack.sh` 顶部参数：`attack_times`（总轮数）、`round_wait_time`（半轮）、`wait_submit_time`（提交前等待）、`run_time`（单目标 timeout）、`next_attack_time`（起进程间隔）、`max_concurrent_attacks`（并发窗口）。
4. 跑一轮先小规模验证：目标数调小、`attack_times=1`，确认 flags 文件有内容、提交接口返回成功。
5. 全量开跑；每轮结束后看 `all_flags` 增长与提交回显，失败目标单独复盘协议/偏移。
6. 赛后整理 `all_flags` 与日志，核对是否有提交失败需要重放。

## PoC

```bash
# 轮次循环骨架（按原文参数简化）
run_time=120; next_attack_time=2.5; max_concurrent_attacks=10
round_wait_time=30; wait_submit_time=5

attack() {
  cat flags >> all_flags; rm -f flags
  local jobs=0
  for line in $(cat hosts); do
    timeout --foreground $run_time python3 ./exp.py "$line" &
    sleep $next_attack_time; ((jobs++))
    [ "$jobs" -ge "$max_concurrent_attacks" ] && { wait; jobs=0; }
  done
  wait; sleep $wait_submit_time
  python3 ./submit_flag.py
}

for ((i=1; i<=attack_times; i++)); do attack $i; sleep $round_wait_time; done
```

```python
# 提交线程池骨架
flags = open("./flags").readlines()
for f in flags:
    threading.Thread(target=submit, args=(f,)).start()
```

说明：原文提交示例用 `os.system` 拼 curl 命令并把 flag 写进 JSON body，实际使用应改为 requests 并对 flag 做转义，避免命令注入与 JSON 破坏；本条未在赛事环境复跑。

## 变体与关联

- 变体：把 bash 作业计数换成 `xargs -P`、`parallel` 或 Python `ThreadPoolExecutor(max_workers=N)`，语义等价但更易读。
- 变体：flag 直接由 exp 返回并写入内存队列，省掉 `flags` 文件；或用 sqlite/csv 记录“目标/轮次/flag/提交状态”便于断点续跑。
- 变体：提交失败重试 + 去重（同一 flag 提交成功过就不再提交），避免赛事接口限流。
- 关联：[[ctf-pwn-awd-batch-scan-concurrent-exp-runner]]（同一 AWD 场景的“扫描 + 动态加载 exp + 结果收集”部分，属 exp 调度层；本条补的是“轮次循环 + flag 归档 + 提交计分”层，两者可串联使用）。
- 边界：并发过高会触发限流/封禁；`timeout --foreground` 在容器/无 tty 环境下行为需确认；提交接口变化、token 过期会让整轮白打。

## 检测与防御

- 防守方检测：短时间对同一 pwn 端口的大量连接、单连接生命周期被 2 分钟级 timeout 截断、多目标同时出现同构交互序列。
- 防守方加固：连接频率限制、异常交互告警；及时修复漏洞使 exp 失效（见 AWDP 补丁卡）。
- 比赛合规：仅在授权靶场/赛事环境使用，遵守赛事对自动提交与频率的规定。
