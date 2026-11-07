---
id: ctf-forensics-soc-dns-tunnel-base32-pat-exfil
title: SOC 编排日志取证：DNS 隧道 + base32 分片外泄 PAT 与 git 配置劫持链
type: scenario
domain: ctf
path: ctf/forensics
technique: soc-log-dns-tunnel-base32-pat-exfil
aliases:
- 谁教坏了我的 Agent
- SOC 告警工单分析
- DNS 隧道取证
- base32 分片还原 PAT
- git 配置劫持
- 编排日志聚合
tags:
- ctf
- forensics
- soc
- dns-tunnel
- base32
- token-leak
- log-analysis
- git-config
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-06'
verification:
  verified_by: verifier-V118
  verified_at: '2026-11-06T02:00:08+08:00'
  notes: 已对照原文核对；EMP_107 四条件唯一性、DNS 固定后缀随机标签、五个 base32 分片拼 PAT、git 配置劫持与六答案格式一致
---

## 一句话结论

题目给出约 11MB 的 SOC 编排日志，需要从 203 名员工/会话中找出同时满足“DNS 查询成功、令牌被风控锁定、越权读取内部文档、git 配置被成功改写”的唯一会话：员工 107 的沙箱在 10:36:14、10:37:51、10:39:26、10:41:05 解析了四个随机标签子域（后缀 `update-check.metrics.e-cdn81.net`，周期约 97/95/99 秒，全部成功），防护组件报告的五个 base32 指纹按序解码得到 PAT `PAT-9F4K2M-Q3GIT7-CORP4S`，该令牌随后被 401 锁定；同一会话还读取了 `asset-inventory-2026Q3.md`，并把 git 拉取地址改写到 `git-cache.corp-fast.net`。按题目格式拼接六个答案即可。

## 原理

- **日志结构**：编排日志每条是 JSON，包含 `session_id`、`event_type`、`result` 等字段；事件类型覆盖 DNS 查询、工具调用、文件读写、HTTP 状态、git 配置变更等。约 203 名员工、11MB 数据，需要先按员工/会话聚合，再逐会话提取证据。
- **唯一性筛选**：题目说明大量被拒绝的越权尝试与编码咨询是噪声；用四个强条件交集缩小到单一会话：
  1. DNS 查询成功且周期性重复；
  2. 员工令牌被风控 401 锁定；
  3. 越权读取内部文档（资产清单）；
  4. git 配置被成功改写。
  只有编号 107 的员工同时满足；编号 73 有几乎相同的链路但 DNS 全部失败且配置写入被策略阻断，编号 134 改写的是镜像源配置且令牌没有被锁定。
- **DNS 隧道特征**：四个随机标签子域的后缀固定为 `update-check.metrics.e-cdn81.net`，查询间隔约 97/95/99 秒，全部返回成功；这种“固定后缀 + 随机标签 + 短周期”是 DNS 隧道/信标（beacon）的典型特征。
- **base32 分片**：防护组件报告中的五个指纹 `KBAVILJZ`、`IY2EWMSN`、`FVITGR2J`、`KQ3S2Q2P`、`KJIDIUY` 是 base32 分片，按序补 `=` 解码后拼接得到完整 PAT `PAT-9F4K2M-Q3GIT7-CORP4S`，与 10:31:12 读取的凭据文件内容一致；第一片还通过遥测字段外传，其余经 DNS 传出。
- **后续影响**：令牌随后被 401 锁定（数据集中唯一 401）；10:31:16 读取资产清单文档，超出 git 审计范围；10:31:21 成功写入 git 配置，把代码拉取地址重定向到 `git-cache.corp-fast.net`，形成供应链风险。
- **答案格式**：恶意注册域 `e-cdn81.net`、完整令牌、受害员工工号 `107`、恶意组件安装完成时间 `20260910T1422`、被越权读取文档 `asset-inventory-2026Q3.md`、代码拉取重定向域 `corp-fast.net`。

## 触发条件

- 日志数据包含 DNS 查询、令牌状态、文件访问、git 配置变更等多源事件，且可按员工/会话关联。
- 攻击者使用 DNS 隧道外带编码分片，分片可由 base32/hex 等规则还原。
- 存在凭据读取、令牌风控锁定与 git 配置劫持的时序链。
- 题目提供答案格式与必答问题，允许用唯一性条件筛选。

## 利用步骤

1. 解析 JSON 日志，按 `session_id`/员工聚合，统计每个会话的事件类型与结果。
2. 过滤 DNS 查询成功且同一后缀、随机标签、周期重复的会话；记录查询时间与子域。
3. 过滤令牌被 401 锁定、越权读取内部文档、git 配置成功改写的会话，取四条件交集。
4. 对命中会话提取凭据读取事件与防护组件指纹，按 base32 解码五个分片并拼接 PAT。
5. 提取恶意注册域、员工工号、组件安装时间、被读文档、git 重定向域，按题目格式拼接提交。

## PoC

```python
import json, base64

path = "orchestration_logs.json"
for line in open(path, encoding="utf-8"):
    d = json.loads(line)
    if (d.get("session_id") == "EMP_107-2026-0915-b41d77e0"
            and d.get("event_type") == "mcp_transaction"
            and d.get("result")):
        print(d["result"]["content"][0]["text"])
        for s in ["KBAVILJZ", "IY2EWMSN", "FVITGR2J", "KQ3S2Q2P", "KJIDIUY"]:
            pad = "=" * ((8 - len(s) % 8) % 8)
            print(s, base64.b32decode(s + pad))
```

DNS 隧道事件筛选（伪代码）：

```python
from collections import defaultdict

sessions = defaultdict(list)
for line in open("orchestration_logs.json", encoding="utf-8"):
    d = json.loads(line)
    sessions[d["session_id"]].append(d)

for sid, events in sessions.items():
    dns = [e for e in events if e.get("event_type") == "dns_query"
           and e.get("result", {}).get("status") == "success"
           and e.get("query", "").endswith("update-check.metrics.e-cdn81.net")]
    locked = any(e.get("http_status") == 401 for e in events)
    doc = any("asset-inventory-2026Q3.md" in str(e) for e in events)
    git = any(e.get("event_type") == "git_config_write" and e.get("result", {}).get("status") == "success"
              for e in events)
    if len(dns) >= 4 and locked and doc and git:
        print(sid, [e["query"] for e in dns])
```

## 变体与关联

- 外带编码可换成 base64、hex、自定义字母表、DNS TXT/AAAA 记录、DoH/DoT；分片可能分散在 User-Agent、遥测字段、DNS 标签中。
- 唯一性筛选条件可换成时间窗口、进程树、文件哈希、网络五元组；核心是“先用强条件缩小到单一会话，再逐字段取证”。
- 关联：DNS 隧道检测、凭据外泄取证、供应链投毒、SOC 日志分析卡。

## 检测与防御

- DNS 侧：监控固定后缀 + 随机标签 + 短周期查询、异常 TXT/AAAA、DoH/DoT 到陌生域名；对高风险域名做 sinkhole 与告警。
- 令牌侧：PAT 最小权限、短期有效期、绑定 IP/设备、异常批量拉取与 401 锁定告警；凭据文件访问审计。
- Git 侧：保护仓库级/全局 git 配置，监控 `url.*.insteadOf`/remote 改写；CI 拉取地址白名单。
- 端点侧：监控 MCP/Agent 工具调用、遥测字段外传、异常编码字符串；对防护组件指纹做解码与关联。
