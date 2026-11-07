---
id: defense-forensics-email-header-spoof-detection
title: 伪造邮件 .eml 的头部溯源与硬信号判定
type: scenario
domain: defense
path: defense/forensics
technique: email-header-provenance-forensics
aliases:
- 邮件头取证
- Received 链分析
- Return-Path 不一致
- 钓鱼邮件溯源
- 伪造邮件识别
tags:
- email
- forensics
- smtp
- received-chain
- return-path
- message-id
- phishing
- spf
- dkim
- dmarc
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-04'
updated: '2026-11-04'
verification:
  verified_by: verifier-C
  verified_at: '2026-11-04T19:05:10+08:00'
  notes: 已对照原文与11张内嵌图核对：三层头部可信度、Received 自下而上、Return-Path/From 域比对、Message-ID 辅助、6000s 时间倒挂与退出码 0/1 均一致；SPF/DKIM/DMARC 配置为原文声明未实测项，未复核
---

## 一句话结论

判断一封 .eml 是否伪造，关键不是读头部写了什么，而是分清每一行是谁写的：Return-Path 与 Received 由投递方写入、改不掉；From、Message-ID 和发信方自带的 Received 都可伪造。优先比对“信封域 vs 显示域”，再自下而上检查 Received 链的时间单调性与主机连续性。

## 原理

- SMTP 维护两套发件人：信封发件人（`MAIL FROM`）用于投递与退信，头部 `From:` 是收件人看到的显示发件人，两者本不必相同。
- 最后一跳 MTA 落盘时按信封发件人写入 `Return-Path`；每一跳 MTA 在头部最上方追加一条 `Received`。因此 `Return-Path` 和 `Received` 是投递过程产生的，攻击者无法在投递前决定。
- `From:`、`To:`、`Subject:`、`Date:`、`Message-ID:` 全部由发信方在投递前写好，单独看都不构成证据；攻击者还可以在正文头部手动塞入伪造的 `Received`。
- Received 链在文件中自上而下存放，等于投递时间倒序。按投递顺序读取必须**自下而上**：最下面是最早一跳，最上面是最近一跳。
- 正常链条的时间应随投递递增（允许少量时钟偏差）。若下方某跳的时间反而晚于上方跳，就是“时间倒挂”，链条不可能这样产生。
- 信封域与显示域不一致，说明显示发件人是假的；Message-ID 的域通常属于真实发信设施，与 From 域不一致可作为辅助信号。

## 触发条件

- 拿到原始 `.eml`（不是转发、截图或二次导出的版本），最好同时有 MTA 投递日志。
- 邮件经过至少一跳真实 MTA，存在可读的 Return-Path/Received。
- 生产环境优先看网关写入的 `Authentication-Results`；本地/无网关环境该行为空，只能退回信封与链条判断。

## 利用步骤（取证判定）

1. 保全原始 `.eml` 与 MTA 日志，记录文件哈希与获取时间。
2. 先看 `Authentication-Results`：有 SPF/DKIM/DMARC 结果就以网关结论为准；fail 可直接取值并提取发信 IP。
3. 没有认证结果时比对 `Return-Path` 与 `From:` 的域；不一致即“显示发件人是假的”。
4. 展开（unfold）所有 `Received` 头，按文件顺序反转得到投递顺序，检查相邻跳时间是否递增、主机名能否衔接。
5. 检查 Received 条数是否与路径匹配；出现“发信方自带”的 Received 或缺失中间跳都可疑。
6. 最后看 Message-ID 的域与时间是否与链条自洽，作为辅助线索；与 MTA 日志交叉核对信封、来源 IP、时间。

## PoC

```python
from email import policy
from email.parser import BytesParser
from email.utils import parsedate_to_datetime

msg = BytesParser(policy=policy.default).parse(open("sample.eml", "rb"))
print("Return-Path:", msg.get("Return-Path"))
print("From:", msg.get("From"))
print("Message-ID:", msg.get("Message-ID"))

# Received 在文件中自上而下 = 投递时间倒序；反转后 hop1 为最早一跳
hops = list(reversed(msg.get_all("Received", [])))
for i, h in enumerate(hops, 1):
    print(f"hop{i}:", " ".join(str(h).split()))
```

```text
# 伪造样本的关键读数
Return-Path: <bounce@mail-relay.test>          # 真实信封域
From: "IT 支持部门" <it-support@example-corp.test>  # 冒充的显示域
Received(文件顺序 1): by sink.test            2026-10-14 15:38:14
Received(文件顺序 2): by inbound.example-corp.test 2026-10-14 17:18:14
# 自下而上：hop1 17:18:14 -> hop2 15:38:14，Δ -6000s，时间倒挂
```

判定：信封域 `mail-relay.test` ≠ 显示域 `example-corp.test`，且 Received 链倒挂 6000 秒，两条硬信号同时命中，结论为疑似伪造。

## 变体与关联

- 变体：只命中域名不一致（单跳直投、没有可比较的时间链）时，仍可定性显示发件人造假。
- 变体：攻击者删除中间 Received 造成跳数缺失；或伪造一条“本公司网关”记录，但主机名/IP 不在资产清单中。
- 变体：Message-ID 时间戳与 Date 不一致、域属于发信设施域；只能作为辅助，不能单独定性。
- 协议坑：Received 头会折叠成多行，按行 split 会把一条记录读成多条，必须先 unfold；SMTP 多行回复（`250-` 续行）与 DATA 点号填充处理错误会导致正文截断、证据失真。
- 关联：生产环境应结合 SPF/DKIM/DMARC 与网关日志；本卡只覆盖信件本身的证据结构。

## 检测与防御

- 检测：`Return-Path` 域与 `From:` 域不一致；Received 自下而上时间不递增；Received 条数与路径不符；Message-ID 域与 From 域不一致。
- 检测：`Authentication-Results` 中 spf/dkim/dmarc 为 fail，或该头缺失得没有道理；结合发信 IP 进封禁流程。
- 防御：为自有域配置 SPF（先 `~all` 后 `-all`）、DKIM（轮换选择器），DMARC 从 `p=none` 观察后收紧到 `quarantine`/`reject`。
- 防御：收信网关统一写入 `Authentication-Results`；MTA 日志至少留存 90 天，保留信封、来源 IP、时间。
- 取证：保留原始 .eml 与对应 MTA 日志；不要只保存转发件或截图，转发会重写头部、破坏证据链。
