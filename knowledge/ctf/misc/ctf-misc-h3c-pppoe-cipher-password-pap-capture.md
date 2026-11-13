---
id: ctf-misc-h3c-pppoe-cipher-password-pap-capture
title: H3C 配置密文密码还原：把 password cipher 导入 PPPoE 路由器做 PAP 拨号，抓包取明文
type: scenario
domain: ctf
path: ctf/misc
technique: h3c-cipher-password-pppoe-pap-cleartext-capture
aliases:
- H3C 密码解密
- password cipher 还原
- PPPoE PAP 抓包
- HCL 模拟器抓密码
- $c$3$ 配置密文
tags:
- h3c
- pppoe
- pap
- credential-recovery
- network-device
- hcl
- wireshark
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V548
  verified_at: '2026-11-11T21:52:10+08:00'
  notes: 已对照原文（xz.aliyun.com/news/13070，2024 L3HCTF Reverse WP 中 hhhc 题）与全部6张图核对：图01 IDA 伪代码显示 CryptAcquireContext/CryptCreateHash/CryptHashData/CryptDeriveKey(0x660E, calg=AES_128)/CryptEncrypt 与 XTEA 逆运算；图02 CALG_AES_128=0x0000660e；图03 内存中 TEA 派生数据；图04 HCL 两台 MSR36-20 直连；图05 右键链路菜单含启动 Wireshark；图06 Wireshark PPP PAP Authenticate-Request，Peer-ID=hustpppoe114514、Password 字段为明文 L3HCTF{ppPOe_mus7_s@v3_plain7ex7_pswdDdD}，证明 PAP 明文抓包链已打通，与卡片一句话结论/原理/步骤/PoC一致。卡内用户名 hustpppoe114514 与原文一致，cipher 以 $c$3$<cipher> 占位合理；原文密文为 $c$3$3PbDU2m2/... 可核对。CTF 无组件版本，不设 affected_versions。dedup 报告 top 候选均 new、无同一利用链；与路由器取证/密码学识别卡为不同场景。未验证点：未在本机搭 HCL 复现；frontmatter 无 sources/source_url（全库惯例）。卡片未修改。
---

## 一句话结论

H3C 设备配置里的 `password cipher $c$3$...` 是**设备自身可逆**的密文，不需要破解算法：把含该密文的配置导入一台支持 PPPoE 的 H3C 路由器（或 HCL 模拟器的 MSR36-20），再让另一台 H3C 路由器把它配成 PPPoE 服务端的 PAP 用户，客户端拨号时 PAP 协议会以**明文**在链路上传输用户名和密码，抓包即可直接读出原始口令。

## 原理

- **`password cipher` 为什么能“还原”**：设备认证时必须拿到明文口令来比对，所以配置里的 cipher 密文对同厂商设备是可逆的；它防的是“看到配置文件的人”，不是“拿到设备的人”。把密文原样配置到另一台 H3C 设备上，该设备同样能解出明文并用于认证。
- **PAP 为什么泄露明文**：PPPoE 拨号在建立会话后由 PPP 的 LCP 协商认证方式；PAP（Password Authentication Protocol）的 Authenticate-Request 报文中 `Peer-ID` 与 `Password` 字段都是明文，只有 CHAP 才会用挑战/响应避免明文传输。因此只要服务端配置 `ppp authentication-mode pap`，客户端拨号时密码必然出现在抓包里。
- **为什么用两台路由器**：把“读取密文”和“触发认证”拆开——客户端路由器持有题目/目标配置里的 cipher 口令并主动拨号，服务端路由器用相同 cipher 配置出可接受该口令的 PAP 用户；两者之间的 PPPoE 链路就是抓包点。HCL（H3C Cloud Lab）模拟器可以完整复现，MSR36-20 支持 PPPoE；交换机型号不支持 PPPoE，不能用于此方法。
- **为什么不需要知道算法**：整个流程不碰 H3C 的密文算法，只利用设备自身把 cipher 当合法配置使用；抓包得到的 PAP Password 字段就是明文口令，等价于“让设备自己解密并读出来”。

## 触发条件

- 能获取目标 H3C 设备的配置（含 `password cipher $c$3$...` 形式的 PPPoE/本地用户口令）。
- 有支持 PPPoE 的 H3C 路由器（真机或 HCL 模拟器中的 MSR 系列；交换机不行）。
- 能在客户端与服务端之间抓包（HCL 中右键链路启动 Wireshark，真机可镜像/串接抓包）。
- 服务端认证方式必须为 PAP；若目标环境强制 CHAP，则抓不到明文，需要换思路。
- 模拟器运行环境需关闭 Hyper-V 等冲突虚拟化（HCL 常见要求）。

## 利用步骤

1. 安装 HCL 模拟器，创建两台支持 PPPoE 的路由器（如 MSR36-20），用链路连接。
2. 客户端路由器导入/粘贴目标配置中的 Dialer 接口与 PPPoE 客户端配置，其中 `ppp pap local-user <用户名> password cipher <密文>` 保持原样：
   - `interface Dialer0`；`ppp pap local-user ... password cipher $c$3$...`；`dialer bundle enable`；`dialer-group 2`；`ip address ppp-negotiate`；`nat outbound`
   - `interface GigabitEthernet0/0`；`pppoe-client dial-bundle-number 0`
3. 服务端路由器配置 PPPoE 服务与 PAP 认证，并用同一段 cipher 密文配置本地用户：
   - `interface virtual-template 1`；`ppp authentication-mode pap domain dm1`
   - `interface gigabitethernet 0/0`；`pppoe-server bind virtual-template 1`
   - `local-user <用户名> class network`；`password cipher $c$3$...`；`service-type ppp`
4. 在连接两台路由器的链路上启动抓包（HCL 右键链路 → 启动 Wireshark）。
5. 触发客户端拨号（`dialer timer autodial` 或手动），在 Wireshark 中过滤 `ppp`/`pap`，查看 `PPP Password Authentication Protocol` 的 `Authenticate-Request` 报文。
6. 直接读取 `Peer-ID` 与 `Password` 字段即为明文用户名和口令。

## PoC

```text
# 客户端（示例，密文原样来自目标配置）
system-view
interface Dialer0
 ppp pap local-user hustpppoe114514 password cipher $c$3$<cipher>
 dialer bundle enable
 dialer-group 2
 dialer timer idle 0
 dialer timer autodial 5
 ip address ppp-negotiate
 nat outbound
 quit
interface GigabitEthernet0/0
 port link-mode route
 pppoe-client dial-bundle-number 0
 quit

# 服务端（PAP + 相同 cipher 用户）
system-view
interface virtual-template 1
 ppp authentication-mode pap domain dm1
 quit
interface gigabitethernet 0/0
 pppoe-server bind virtual-template 1
 quit
local-user hustpppoe114514 class network
 password cipher $c$3$<cipher>
 service-type ppp
 quit
```

```text
# 抓包判据：Wireshark 过滤 ppp，查看 Authenticate-Request
Point-to-Point Protocol
  PPP Password Authentication Protocol
    Code: Authenticate-Request (1)
    Peer-ID-Length / Peer-ID: <用户名>
    Password-Length / Password: <明文口令>   <- 直接读取
```

## 变体与关联

- 关联：[[ctf-forensics-pcap-wifi-router-takeover-chain]]（路由器相关流量的取证思路，本卡是从配置密文反推口令的实验方法）、[[code-analysis-reverse-crypto-encoding-identification-decrypt]]（离线识别与解密思路；本卡的特点是**不破解算法**而借设备自身行为取明文）。
- 变体：真机 H3C 路由器 + 串接抓包同样可行；若服务端支持，也可让模拟器作客户端、真机作服务端；其他厂商设备只要“配置密文可被同厂商设备直接使用”且认证为 PAP，也可套用同样思路；PPPoE 之外，PAP 还见于部分串口/DSL 拨号场景。
- 边界：CHAP/MS-CHAP 不会明文传密码，此方法失效；H3C 交换机不支持 PPPoE；HCL 需要关闭 Hyper-V 且依赖特定版本；若目标配置的密文来自不支持导入的格式（如部分型号的 `password hash` 单向散列），无法用设备回读。

## 检测与防御

- 检测（防御方视角）：核心设备配置中的 PPPoE 口令若为可逆 `cipher`，应视为已泄露风险；监测网络中异常的 PPPoE 服务端/客户端拨号与 PAP 认证；检查配置文件的传播范围。
- 防御：广域网/PPPoE 认证改用 CHAP 或更安全的认证方式，避免 PAP 明文口令；严格保护设备配置文件（加密存储、限制导出权限），配置泄露后立即轮换所有相关口令；不要把 `password cipher` 当作安全的密码存储形式。
