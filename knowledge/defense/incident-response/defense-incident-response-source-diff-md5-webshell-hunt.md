---
id: defense-incident-response-source-diff-md5-webshell-hunt
title: 源码基线对比 + 文件哈希找 webshell：diff 新增行定位 eval/一句话马
type: scenario
domain: defense
path: defense/incident-response
technique: source-baseline-diff-md5-webshell-hunt
aliases:
- diff 找 webshell
- 源码对比排查后门
- MD5 对比找修改文件
- 文件哈希基线
- 代码差异定位篡改
- eval($_POST) diff
tags:
- incident-response
- webshell
- diff
- md5
- file-integrity
- php
- forensics
- triage
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V597
  verified_at: '2026-11-12T16:55:42+08:00'
  notes: 已对照原文与 23 张图核对：img/23 diff -c -a -r 输出 *** 1/index.php/--- html/index.php 时间戳与 + eval([1]); 新增行与卡一致；MD5 基线对比与 Python hashlib 清单脚本为对原文'对比前后文件哈希'的等价实现，PoC 可执行。Windows 隐藏/克隆账号（SAM F 值 000001F4->000003EA、导出导入）已被 pentest-persistence-windows-sam-f-value-shadow-account-clone 覆盖，其余 Windows/Linux 清单已被 windows-cli-only-triage-command-matrix、windows-persistence-triage-run-schtask-service、linux-web-intrusion-triage-checklist、bash-history-hydra-useradd-uid0、linux-ssh-bruteforce-sshd-backdoor-mining-kinsing 覆盖，跳过合理；anacron 仅原文用法说明无攻击链，不单独成卡（已在 verify.json 记录）。dedup 候选 dshield-level-webshell-triage（特征分级查杀）与各流量解密卡均非同链；dup-scan 无涉及本卡 pair。原文未标版本，versions 留空。
---

## 一句话结论

当攻击者是在正常 PHP 文件里插入 `eval($_POST[...])` 一句话、或新增少量后门文件时，把当前 Web 根目录与干净备份/发行包做 `diff -c -a -r` 递归对比，直接看带 `+` 的新增行即可定位后门；文件较多时先按 MD5 哈希清单对比，把“新增/被改”的文件收敛到少数再逐个 diff。

## 原理

- 篡改型 webshell 的典型形态是在现有文件里加一行 `eval($_POST[1]);`、`assert(...)`、`base64_decode(...)` 或文件包含语句；文件大小、功能几乎不变，静态查杀可能漏报，但与原始版本逐行对比一定会暴露新增行。
- `diff -c -a -r dir1 dir2` 递归比较两个目录：`-c` 输出上下文格式，新增行以 `+` 开头、删除行以 `-` 开头、`***/---` 标出两侧文件与时间戳；`-a` 把文件当文本处理，避免二进制误判跳过。攻击者新增的 eval 行会以 `+ eval($_POST[1]);` 形式直接出现在输出里。
- 哈希对比解决“文件太多”的问题：对每个文件算 MD5/SHA1，与基线清单求差集——路径只在当前目录出现的为新增文件（常是上传马/日志马），哈希不一致的为被修改文件（常是一句话插入）。先收敛名单，再做 diff 看具体改动。
- 为什么有效：攻击者必须修改文件内容才能落地 webshell；而正常业务发布通常有备份、压缩包或版本库作为基线。完整性对比不依赖特征库，对未知/变形后门同样有效。
- 前提是基线可信：备份/发行包必须是入侵前或干净版本，否则对比无意义；同时要看 mtime 辅助判断（被 diff 命中的文件修改时间应集中在入侵时间窗）。

## 触发条件

- 已获取当前 Web 根目录（主机 shell、镜像或打包副本）以及入侵前的干净备份、同版本发行包或 git 历史。
- Web 应用为 PHP/ASP/JSP 等文本源码形态，后门以新增行/新增文件形式存在。
- 有 diff、md5sum/sha1sum 等基础命令，或可在离线环境运行脚本。
- 文件数量可控或可先按目录/哈希清单分批比较。

## 利用步骤

1. 固定证据：对当前 Web 根目录打包并记录哈希、时间与来源，先不删除任何文件。
2. 准备基线：取入侵前备份/官方发行包/版本库导出（同版本），解压到独立目录。
3. 哈希清单对比（先收敛）：分别对两份目录生成 `md5sum` 清单（`find . -type f -exec md5sum {} + | sort -k2`），用 `diff`/`comm` 找出新增路径与哈希不一致路径。
4. 逐文件 diff（再定性）：对可疑文件执行 `diff -c -a -r base/ current/`（或单文件 `diff -u`），重点看 `+` 行中的 `eval`、`assert`、`base64_decode`、`include`、`$_POST/$_GET/$_REQUEST`。
5. 关联时间线：`stat` 命中文件的 mtime/ctime，与访问日志中的上传/写入请求、入侵时间窗对齐。
6. 处置：隔离样本与日志，删除后门并修复入口；对同批新增文件做全量排查，轮换凭据并复查。
7. 若命中文件很多（如整站被批量插入），优先按目录/最近修改时间缩小范围，再对比。

## PoC

```bash
# 1) 递归对比，直接看新增行（示例输出）
diff -c -a -r cms1 cms2
# *** 1/index.php   2024-01-21 00:57:00 ...
# --- html/index.php 2024-01-21 00:56:00 ...
# ***************
# *** 1,4 ****
# --- 1,5 ----
# + eval($_POST[1]);

# 2) 先生成哈希清单，找新增/被改文件
find base -type f -exec md5sum {} + | sed 's# base/# #' | sort -k2 > base.md5
find current -type f -exec md5sum {} + | sed 's# current/# #' | sort -k2 > cur.md5
diff base.md5 cur.md5
```

```python
# 批量计算目录内文件 MD5（标准库）
import hashlib, os, sys

def md5sum(path):
    h = hashlib.md5()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(8192), b''):
            h.update(chunk)
    return h.hexdigest()

root = sys.argv[1]
for dirpath, _, files in os.walk(root):
    for name in files:
        p = os.path.join(dirpath, name)
        print(md5sum(p), os.path.relpath(p, root))
```

## 变体与关联

- 变体：`git status`/`git diff`（站点在版本库中）；`rpm -Va`/`dpkg --verify` 校验系统包文件；AIDE/Tripwire 等文件完整性监控；按 mtime 时间窗 `find -newermt` 先筛再 diff；WordPress/Discuz 等用官方包覆盖对比。
- 关联：与[[defense-incident-response-dshield-level-webshell-triage]]互补——D盾按特征分级扫描，本卡按完整性差异找未知/变形后门；[[defense-incident-response-linux-web-intrusion-triage-checklist]]提供整体排查顺序，本卡是其中“文件层”的细化。
- 边界：无干净基线时不可用，需改用静态查杀+日志+流量回溯；攻击者删除/篡改基线或整站替换时 diff 失效。

## 检测与防御

- 防御：代码上线走不可变镜像/容器，运行目录只读；保留同版本干净发行包与哈希清单；对 Web 目录部署文件完整性监控（AIDE/Wazuh/FIM），变更告警。
- 检测：监控 Web 目录新增 `.php` 与内容变更（尤其 uploads/runtime/log 等可写目录），对 `eval/assert/base64_decode` 新增行告警；发布流程外的手工改文件即高危信号。
