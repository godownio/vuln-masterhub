---
id: defense-detection-lockbit3-encrypted-file-artifacts
title: LockBit 3 加密文件与勒索信现场识别
type: scenario
domain: defense
path: defense/detection
technique: lockbit3-file-artifacts
tags:
- ransomware
- lockbit
- detection
- incident-response
- file-artifacts
- windows
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-04'
updated: '2026-11-04'
verification:
  verified_by: verifier-H
  verified_at: '2026-11-04T19:41:01+08:00'
  notes: 来源 93088；已对照原文及 Everything 截图核对；文件名结构按截图补正为 10 位随机串 + 点 + [邮箱] + 点 + 8 位扩展名；黑底白边 B 图标、DataRecovery.txt、05:29 至 05:30 加密时间窗均一致；其他 LockBit 构建未验证。
url: /docs/defense/detection/defense-detection-lockbit3-encrypted-file-artifacts/
draft: false
kb_aliases:
- LockBit 3 识别
- LockBit 加密文件命名
- 黑底白边 B 图标
- DataRecovery.txt
- 勒索家族判别
---

## 一句话结论

LockBit 3 加密后的文件具有较稳定的现场特征：文件名变为“10 位随机字母数字 + `.` + `[联系邮箱]` + `.` + 8 位随机扩展名”，文件图标被替换为黑底白边的大写 B，目录中留下 `DataRecovery.txt` 勒索信；这些特征可用于快速确认家族、划定加密时间窗和判断处置优先级。

## 原理

LockBit 3（LockBit Black）加密器在加密文件时会：

- 把原文件名替换为随机字符串，并在名字中嵌入受害者联系邮箱和随机扩展名，便于受害者按邮件联系；
- 通过资源替换把文件图标改成黑底、白边、大写字母 B 的家族标志；
- 在桌面（及部分加密目录）放置勒索信（常见名 `DataRecovery.txt`），内容包含受害者 ID、Tor 谈判地址或邮箱；
- 批量修改文件内容与时间戳，同一批文件的修改时间集中在几分钟内。

不同受害者、不同构建的扩展名和邮箱会变化，因此不能只靠固定扩展名判断；应组合文件名结构、图标、勒索信、加密时间分布和加密器哈希。

## 触发条件

- Windows 主机或共享目录出现大量文件同时被改名、图标变化；
- 文件名符合“随机串 + 邮箱 + 随机扩展名”结构；
- 目录中存在勒索信文本；
- 文件修改时间集中在数分钟内，且业务不可用；
- 能在内存/磁盘找到加密器样本或执行痕迹（Amcache、Prefetch、EDR）。

## 利用步骤

（本卡为检测与应急识别，不提供加密操作。）

1. 用 Everything/文件服务器检索按修改时间排序，圈定批量改名的时间窗；
2. 抽样文件名，检查是否匹配“随机 10 位 + 邮箱 + 8 位扩展名”；
3. 查看文件图标是否变为黑底白边大写 B；
4. 搜索 `DataRecovery.txt`、`Restore-My-Files.txt` 等勒索信，记录联系邮箱与受害者 ID；
5. 在 Amcache/Prefetch/EDR 中找加密器执行记录，计算哈希；
6. 隔离主机、保留样本与日志，再评估备份恢复。

## PoC

文件名结构近似正则（以实际样本为准）：

```regex
^[A-Za-z0-9]{10}\.\[[^\]\s]+@[^\]\s]+\]\.[A-Za-z0-9]{8}$
```

现场检索命令示例：

```powershell
# 按修改时间找批量加密窗口
Get-ChildItem -Path C:\ -Recurse -File -ErrorAction SilentlyContinue |
  Where-Object { $_.LastWriteTime -gt '2026-08-20 05:25' -and $_.LastWriteTime -lt '2026-08-20 05:35' } |
  Select-Object FullName, Length, LastWriteTime -First 100

# 找勒索信
Get-ChildItem -Path C:\ -Recurse -Filter 'DataRecovery.txt' -ErrorAction SilentlyContinue

# 查看文件图标替换情况（人工抽样）
```

加密器哈希可作为家族佐证，但哈希会随构建变化，不能作为唯一判据。

## 变体与关联

- 变体：LockBit 2/Black 的扩展名策略不同；部分构建使用固定扩展名或不同勒索信文件名；图标也可能未被替换。
- 关联：[[defense-incident-response-ransomware-pre-encryption-cleanup]]（加密前的清日志、停服务、删备份行为）；[[defense-forensics-multisource-timeline-log-clear]]（日志被清后的时间线重建）。
- 不确定点：文件名随机串长度、扩展名长度可能随构建变化；应结合勒索信与样本哈希确认，不要仅凭扩展名归因。

## 检测与防御

- 检测：短时间大量文件改名/图标变化；勒索信文件名；文件熵骤升；共享目录写入异常；加密器进程与已知哈希。
- 响应：立即隔离受感染主机与共享，冻结备份，保留勒索信、样本、日志与内存；不要支付赎金；从离线/不可变备份恢复。
- 防御：最小权限与网络分段，禁用不必要的 SMB/RDP 暴露；EDR 行为规则监控批量改名与日志清除；备份离线且定期演练恢复。
