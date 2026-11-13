---
id: defense-incident-response-linux-miner-dotidea-lolminer-mine-doge-pool-wallet
title: Linux 挖矿入侵取证：/etc/passwd 新增用户 + 用户目录 .log.txt 外联 IP + 隐藏 .idea 目录中 lolMiner/mine_doge.sh 的矿池与钱包
type: scenario
domain: defense
path: defense/incident-response
technique: linux-miner-artifact-triage-dotidea-lolminer-doge
aliases:
- 陇剑杯 sevrer save
- lolMiner 取证
- mine_doge.sh
- .idea 隐藏挖矿
- DOGE 钱包地址取证
- 挖矿病毒用户与日志排查
tags:
- incident-response
- linux
- forensics
- mining
- lolminer
- dogecoin
- pool
- wallet
- hidden-directory
- ctf
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V682
  verified_at: '2026-11-13T13:49:33+08:00'
  notes: 已对照原文与36图核对：图04 /etc/passwd 的 guests/11 均 uid0、图05 home 下 .idea/.log.txt/main(18,345KB)、图06 shadow 中 11 口令 123456、图07/08 .log.txt Query 172.105.202.239 与 .idea/mine_doge.sh、图09/10 POOL=doge.millpools.cc:5567 与 WALLET=DOGE:DRXz1q6ys8Ao2KnPbtb7jQhPjDSqtwmNN9.lolMinerWorker（while [ $? -eq 42 ]）。修正一处 while 条件括号笔误。dedup top（docker 挖矿 triage/ssh 爆破挖矿/uid0 持久化等）非同一条证据链。skip 抽查：Spring4Shell、PgJDBC、前端 AES、Flask session 引用卡均在库且覆盖理由成立。原文无版本标记，未设 affected_versions。未在本环境复现。
---

## 一句话结论

Linux 主机/磁盘镜像疑似挖矿时，按“`/etc/passwd` 异常账户 → 用户目录可疑 ELF → 同目录 `.log.txt` 的外联 IP 与执行痕迹 → 隐藏 `.idea` 目录中的挖矿脚本与二进制 → 脚本内 `POOL`/`WALLET`”这条链可在不跑样本的情况下还原事件：本例病毒 `main` 创建了用户 `11`（口令 `123456`），日志记录外联 IP `172.105.202.239`，`.idea` 下释放 `lolMiner` 与 `mine_doge.sh`，矿池 `doge.millpools.cc:5567`、钱包 `DOGE:DRXz1q6ys8Ao2KnPbtb7jQhPjDSqtwmNN9`。

## 原理

- **账户面**：挖矿/入侵脚本常创建不易察觉的账户或复用弱口令。`/etc/passwd` 中出现与业务无关的 `11:x:0:0::/home/11:/bin/sh`、`guests:x:0:0::/home/guests:/bin/sh` 这类 uid 0 账户即可疑；`/etc/shadow` 中 `11:openssl passwd -1 -salt 'salt' 123456:...` 直接暴露该账户口令是按 `123456` 生成的 MD5 crypt。
- **文件面**：进入该用户 home（`/home/guests`）可看到大体积 `main`（约 18 MB，ELF）——挖矿木马/投放器常以无扩展名的 `main`、`kworker`、`系统伪装名` 落地；`.log.txt` 与 `.idea` 是常见伴随文件/隐藏目录（`.idea` 本是 IDE 工程目录，攻击者把矿工与脚本放进去降低被 `ls` 注意的概率）。
- **日志面**：`.log.txt` 记录运行过程：`Query: 172.105.202.239`（外联/查询 IP）、`exec: "setenforce": executable file not found`、`fork/exec sh .idea/mine_doge.sh: no such file or directory`（失败尝试）。即使恶意脚本后来被删，日志仍留下 IP 与释放路径。
- **脚本面**：`mine_doge.sh` 头部是用户可编辑区：
  ```bash
  POOL=doge.millpools.cc:5567
  WALLET=DOGE:DRXz1q6ys8Ao2KnPbtb7jQhPjDSqtwmNN9.lolMinerWorker
  ...
  ./lolMiner --algo ETHASH --pool $POOL --user $WALLET ... --4g-alloc-size 4024
  while [ $? -eq 42 ]; do sleep 10s; ... done
  ```
  矿池便于阻断/溯源，钱包地址便于资金追踪/关联其他受害主机；`while [ $? -eq 42 ]` 是崩溃自动重启的常见写法。
- **为什么按这个顺序**：账户是权限维持与运行主体；home 目录下的 ELF/日志是投放器留下的第一现场；隐藏目录里的脚本同时提供“矿池 + 钱包 + 持久化命令”，是完整证据链的核心；最后再与 pcap/进程/网络连接交叉验证外联 IP。

## 触发条件

- 已取得 Linux 主机 shell、磁盘镜像或文件系统快照；可读 `/etc/passwd`、`/etc/shadow` 与用户 home。
- 主机存在异常 CPU 占用/外联/可疑账户，或 CTF 给出服务器镜像与流量。
- 需要定位挖矿样本、矿池、钱包与攻击者基础设施。

## 利用步骤

1. 账户枚举：`cat /etc/passwd` 与 `awk -F: '$3==0' /etc/passwd` 找 uid 0 的异常账户；`cat /etc/shadow` 找可疑哈希（`openssl passwd -1` 格式可直接识别弱口令）。
2. 进入可疑用户 home：`ls -la /home/guests`，对无扩展名大文件用 `file`/`strings` 确认 ELF 与功能。
3. 读日志：`cat .log.txt`，记录外联 IP、失败的 exec 与释放路径。
4. 查隐藏目录：`ls -la .idea`，识别 `lolMiner` 与 `mine_doge.sh`。
5. 读脚本：`grep -E "POOL|WALLET|lolMiner" mine_doge.sh`，提取矿池地址与钱包；如需命令行参数可用 `strings lolMiner | grep -i pool`。
6. 与 pcap/`ss`/进程记录交叉验证外联 IP 与矿池连接，形成时间线。

## PoC

```bash
cat /etc/passwd
cat /etc/shadow
# 11:openssl passwd -1 -salt 'salt' 123456:...  -> 口令 123456

ls -la /home/guests
file /home/guests/main
cat /home/guests/.log.txt
# Query: 172.105.202.239
# fork/exec sh .idea/mine_doge.sh: no such file or directory

ls -la /home/guests/.idea
cat /home/guests/.idea/mine_doge.sh
# POOL=doge.millpools.cc:5567
# WALLET=DOGE:DRXz1q6ys8Ao2KnPbtb7jQhPjDSqtwmNN9.lolMinerWorker
# ./lolMiner --algo ETHASH --pool $POOL --user $WALLET ...
```

## 变体与关联

- **矿工家族不同**：XMRig/kinsing 等的矿池/钱包可能保存在配置文件、内存或进程参数中，参考 `[[defense-forensics-xmrig-monero-payment-id-pool-tracking]]`；本卡是 lolMiner + shell 脚本的 Doge 场景。
- **隐藏位置不同**：`.idea` 可换成 `.config`、`.local`、`/dev/shm`、`/tmp`、`ProgramData` 等；关键是查 home 下隐藏目录与近时间修改的大文件。
- **入口关联**：同一题面前半段的 pcap 显示入口是 Spring `CVE-2022-22965`（class.module.classLoader 写 JSP webshell）再下载 `bbbb.sh` 反弹 shell，见 `[[web-java-framework-spring-cve-2022-22965-accesslogvalve-webshell]]`；挖矿是提权后的后续行为。
- 关联：`[[defense-incident-response-linux-ssh-bruteforce-sshd-backdoor-mining-kinsing]]`、`[[defense-incident-response-docker-tomcat-mining-triage]]`、`[[defense-incident-response-linux-web-intrusion-triage-checklist]]`。

## 检测与防御

- **检测**：监控 `/etc/passwd`/`/etc/shadow` 变更（新增 uid 0 账户、`openssl passwd` 哈希特征）；审计 home 下隐藏目录新增可执行文件；检测 `lolMiner`/`xmrig` 等矿工进程与 `*.millpools.cc`/矿池域名连接；关注 `.log.txt` 一类运行时日志中的外联 IP。
- **防御**：禁止 home 可执行（`noexec`）；限制用户创建账户；及时删除异常账户与 SUID；对矿池域名/IP 做出口阻断；定期备份并比对账户与文件基线。
- **响应**：保留样本、脚本与日志副本；提取矿池/钱包用于溯源；清除账户、进程、脚本与隐藏目录后复查持久化（cron/systemd/rc.d/authorized_keys）。
