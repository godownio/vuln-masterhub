---
id: iot-protocol-zkteco-4370-comkey-reversible-mac-auth
title: ZKTeco 4370/TCP 协议 COMKey 认证缺陷：默认 0 + 6 位可爆破 + 可逆 MAC 从抓包还原口令
type: scenario
domain: iot
path: iot/protocol
technique: zkteco-4370-comkey-reversible-mac
aliases:
- ZKTeco COMKey
- 4370/TCP 协议认证
- CMD_AUTH MAC 还原
- zk-protocol COMKey 爆破
- 熵基终端协议口令
tags:
- iot
- zkteco
- biometric-terminal
- protocol
- authentication
- mac
- brute-force
- credential-recovery
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V322
  verified_at: '2026-11-08T15:54:52+08:00'
  notes: 已对照 content.md 与 img01-48 核对：默认 COMKey=0、0-999999 上限、sub_1F520 可逆 MAC 与数据库明文均与原文及 img35-37 一致；PoC 未在真机复跑。原子性：本卡是同一 COMKey 认证机制的多种取钥路径，属一条认证绕过场景，非并列独立技术，不判过粗。
---

## 一句话结论

ZKTeco 生物识别终端在 4370/TCP 上使用的专有协议以 "COMKey" 作为认证口令：默认值为 0（等于无认证），取值范围仅 0–999999（可暴力破解），且 `CMD_AUTH` 的 MAC 生成只用了可逆的位反转、加法与 XOR/循环移位，攻击者抓到一次合法认证的 SessionId 与 MAC 就能反推出 COMKey；COMKey 又以明文存在设备数据库中，任何文件读取或 SSH 登录都能直接拿到。

## 原理

- **协议认证流程**：客户端连 4370/TCP 后发送 `CMD_CONNECT (0x03e8)`，服务器返回 2 字节 `SessionId`；客户端用 COMKey 与 SessionId 计算 MAC，通过 `CMD_AUTH (0x044e)` 发送，服务器校验后回 `CMD_ACK_OK (0x07d0)`，之后当前 TCP 会话可执行所有已实现命令。
- **默认口令**：管理员在设备菜单设置 COMKey，默认 0，即所有请求无需认证即可执行。未修改默认值的终端相当于协议完全未授权。
- **可爆破范围**：设置界面把 COMKey 限制为 0–999999 的整数（原文代码用 `strtol` 后 `SetOptionIntValue("COMKey")`，输入框最大长度 6），只有一百万种可能，网络协议允许快速枚举。
- **MAC 可逆**：原文反编译的 MAC 函数 `sub_1F520(COMKey, SessionId)` 逻辑为：
  1. 对 `i=0..31`，取 COMKey 的第 i 位，若为 1 则 `v2=(2*v2)|1`，否则 `v2*=2`——等价于 `v2 = bitreverse32(COMKey)`；
  2. `v5 = SessionId + v2`（32 位加法）；
  3. `LOWORD(v7) = v5 ^ 0x4B5A`、`BYTE2(v7) = BYTE2(v5) ^ 0x53`、`HIBYTE(v7) = HIBYTE(v5) ^ 0x4F`；
  4. 返回 `ROR4(v7,16)`（高低 16 位互换）。
  这些操作全部可逆：抓到 `SessionId` 与 `MAC` 后，反算 `v5`、减去 SessionId、再做一次位反转即可得到 COMKey，无需爆破。
- **明文存储**：COMKey 以未加密形式保存在设备数据库；任意文件读取漏洞（如协议内的下载命令）或 SSH 登录读取数据库即可获得。
- **影响**：拿到 COMKey 后可执行协议内的文件下载/上传、删除、固件更新等命令；这些命令处理器本身若存在路径穿越/命令注入/溢出，则直接升级为 root 命令执行。

## 触发条件

- 攻击者能访问终端 4370/TCP（默认开放；原文另一端口 3718 为 SSH）。
- 目标 COMKey 为默认 0，或攻击者能在 0–999999 内爆破，或能抓到一次合法认证流量，或能通过文件读取/SSH 读取数据库。
- 协议文档公开（zk-protocol），数据包结构可自行实现；目标未做来源 IP 白名单/速率限制。

## 利用步骤

1. 连接 4370/TCP，发送 `CMD_CONNECT (0x03e8)`，解析返回的 2 字节 `SessionId`。
2. 先按默认 COMKey=0 计算/构造认证（或直接尝试执行目标命令），确认是否免认证。
3. 若需要口令：在 0–999999 内枚举 COMKey，按 MAC 算法计算并发送 `CMD_AUTH`，观察是否返回 `CMD_ACK_OK`；注意控制速率避免锁定/告警。
4. 若能抓到一次合法客户端的 `CMD_CONNECT`/`CMD_AUTH` 流量，记录 SessionId 与 MAC，用反算脚本还原 COMKey（见 PoC）。
5. 通过任意文件读取漏洞或 SSH（如 zkteco 账号）读取设备数据库，直接取 COMKey 明文。
6. 认证成功后复用会话执行后续命令（下载/上传/删除/更新）；仅在授权测试中验证到读取一个无害文件或执行 `id` 为止。

## PoC

MAC 反算（按原文反编译逻辑实现，未对真实设备跑）：

```python
def bitrev32(x):
    r = 0
    for i in range(32):
        r = (r << 1) | ((x >> i) & 1)
    return r & 0xFFFFFFFF

def rol32(x, n):
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF

def recover_comkey(session_id, mac):
    v7 = rol32(mac, 16)                       # ROR4(v7,16) 的逆
    low16 = (v7 & 0xFFFF) ^ 0x4B5A
    b2 = ((v7 >> 16) & 0xFF) ^ 0x53
    b3 = ((v7 >> 24) & 0xFF) ^ 0x4F
    v5 = (b3 << 24) | (b2 << 16) | low16
    v2 = (v5 - session_id) & 0xFFFFFFFF
    return bitrev32(v2)

# 校验：COMKey 应在 0..999999
```

协议交互（概念）：

```text
Client -> Server: CMD_CONNECT (0x03e8)
Server -> Client: SessionId (2 bytes)
Client -> Server: CMD_AUTH (0x044e) + MAC
Server -> Client: CMD_ACK_OK (0x07d0)
```

## 变体与关联

- 变体：COMKey 非默认时先爆破（0–999999），或用一次合法认证流量反算，或从数据库/备份/内存中直接读取。
- 变体：部分固件可能对认证失败做延迟/锁定，需要慢速枚举或直接走数据库读取。
- 关联：[[iot-protocol-zkteco-standalonecomm-delete-picture-command-injection]]（认证后的命令处理器命令注入）、[[iot-protocol-zkteco-standalonecomm-download-picture-path-traversal]]（认证后的任意文件读取）、[[iot-protocol-zkteco-pushcomm-shell-command-server-hijack]]（另一服务的命令执行）。
- 边界：COMKey 已改为强随机值且设备限速、4370 端口被网络隔离、固件修复 MAC 算法/强制非默认口令时，本卡的攻击面下降。

## 检测与防御

- 检测：4370/TCP 上短时间内大量 `CMD_CONNECT`/`CMD_AUTH` 失败；同一来源枚举六位数字；异常会话执行下载/删除/更新命令；设备日志出现协议认证失败。
- 防御：把 COMKey 从默认 0 改为强随机值并定期轮换；限制 4370/TCP 仅允许可信管理网访问；在网关/防火墙做速率限制与来源白名单。
- 加固：升级固件修复可逆 MAC 与明文存储；协议认证改为 HMAC/挑战响应；所有服务以最小权限运行，避免协议漏洞直接获得 root。
