---
id: defense-forensics-security-evtx-account-persistence-4720-4727-4728-audit
title: Security.evtx 账户持久化取证：4720/4726/4727/4728 事件还原攻击者建组建用户加域管的操作序列，再以 ntds.dit+SYSTEM 离线提 hash 用 john 爆破出新用户明文密码
type: scenario
domain: defense
path: defense/forensics
technique: security-evtx-account-persistence-4720-4727-4728-forensics-ntds-john-crack
tags:
- defense
- forensics
- windows
- evtx
- account-persistence
- ntds-dit
- secretsdump
- john
severity: medium
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T1-34
  verified_at: '2026-11-08T17:59:48+08:00'
  notes: 已对照原文与图核对：img52 4727建组maintainer、img53 4728 James加入Domain Admins、img55 4720建用户James、img59 secretsdump导出hash、img61 James NTLM条目均佐证；john爆破结果截图为外链未在本地存档，作为未验证点；与evtx链重建卡事件集不同，差异成立
url: /docs/defense/forensics/defense-forensics-security-evtx-account-persistence-4720-4727-4728-audit/
draft: false
kb_aliases:
- 4720 创建用户取证
- 4727 新用户组
- 4728 加组
- ntds.dit 离线爆破
- fulleventlogview
---

## 一句话结论

攻击者在域控上建组建用户并加入域管理员组实现持久化后，取 Windows/System32/winevt/Logs/Security.evtx 用 fulleventlogview 按攻击时间窗过滤，按事件 ID 排序查 4727（创建全局组，如 maintainer）、4720（创建用户，如 James）、4728（James 加入 Domain Admins 与 maintainer 两条）、4726（批量删除其他诱饵用户）还原完整操作序列；再用 Windows/NTDS/ntds.dit + System32/config/SYSTEM 离线 `secretsdump.py -ntds ntds.dit -system SYSTEM LOCAL` 提出全部用户 NTLM hash，`john -format=NT --wordlist=rockyou.txt` 爆出新用户明文密码（如 3011liverpool!）。

## 原理

- 自 Vista/2008 起，账户与组的创建、删除、加组全部进 Security 日志：4720 创建用户、4726 删除用户、4727 创建全局组、4728 添加成员到全局组，事件正文含使用者（发起者 SID/账户名/登录 ID）、新账户 SID（RID 可判断创建序号）、组成员 DN（CN=James,CN=Users,DC=hack,DC=com）与目标组名（Domain Admins/maintainer）。
- 攻击者常批量创建再删除用户做掩护，仅保留一个加组的后门用户；按 4727 唯一记录锁定组名，4728 两条记录确认该用户同时进了域管组与新组，即锁定持久化三要素（组名-用户名-密码）。
- 密码还原走离线路线：ntds.dit 存全部域账户加密哈希，SYSTEM hive 含解密所需系统密钥（bootKey）；impacket secretsdump 离线解析输出 `域账户:RID:aad3b...:NTLM:::` 三元组；NTLM 为无盐哈希，rockyou 字典 john 爆破即可出弱口令明文。
- evtx 用 fulleventlogview 单独打开并按时间范围过滤（攻击时间窗可由镜像内其他文件修改时间锚定，如 24/12 月）能大幅缩小样本。

## 触发条件

- 已获取域控镜像或 Security.evtx、ntds.dit、SYSTEM 文件。
- 攻击者的账户操作未被清除（删除用户仍有 4726 记录，加组/建组记录通常保留）。

## 利用步骤

1. winevt/Logs 定位 Security.evtx，复制本地用 fulleventlogview 打开。
2. 按 Event Time 过滤攻击时间窗（如 2024/12），按事件 ID 排序。
3. 找 4727：唯一的新全局组名（maintainer）及发起者（Administrator/HACK）。
4. 找 4720：逐条看新账户名，配合 4726（已删除用户）排除被删的诱饵账户，锁定保留的 James。
5. 找 4728：两条记录分别是 James 加入 Domain Admins 与 maintainer，读取成员 DN 与组 SID（-512/-3194）确认。
6. 取 Windows/NTDS/ntds.dit 与 System32/config/SYSTEM，`secretsdump.py -ntds ntds.dit -system SYSTEM LOCAL` 输出全部用户 hash（含 james:3193:...:NTLM:::）。
7. 整理 `用户:RID:...:NTLM:::` 到 txt，`john -format=NT --wordlist=/usr/share/wordlists/rockyou.txt hash.txt` 爆破新用户明文密码。

## PoC

```bash
secretsdump.py -ntds ntds.dit -system SYSTEM LOCAL
john -format=NT --wordlist=rockyou.txt hash.txt
```

## 变体与关联

- 在线路线：secretsdump.py -dc-ip 远程 DRSUAPI 导出（见 Zerologon 等卡的后续），或 DCSync；本卡为镜像离线取证场景。
- 4732（本地组成员变更）、4740（锁定）等事件可扩展同一审计框架。

## 检测与防御

- SIEM 实时告警 4720/4727/4728 且发起者非标准运维账号、新组名异常、用户被加入 Domain Admins。
- 强密码策略 + LAPS；定期检查域内非常规全局组与RID 尾号新建账户。
- 限制普通账户对 ntds.dit/SYSTEM 的访问，开启日志清除告警（1102）。
