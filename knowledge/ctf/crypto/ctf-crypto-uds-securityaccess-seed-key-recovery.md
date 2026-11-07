---
id: ctf-crypto-uds-securityaccess-seed-key-recovery
title: UDS 0x27 SecurityAccess 弱 seed-key 算法逆推：XOR/ROL/ADD 从 seed 计算 key
type: scenario
domain: ctf
path: ctf/crypto
technique: uds-securityaccess-seed-key
aliases:
- UDS SecurityAccess
- 0x27 服务
- seed-key 算法
- 汽车诊断安全访问
- ez_uds
tags:
- ctf
- crypto
- uds
- automotive
- seed-key
- protocol
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V124
  verified_at: '2026-11-06T04:13:41+08:00'
  notes: 已对照原文核对：27 01/67 01/27 02 流程、key = ROL32(seed^0xA5A5A5A5,3)+0x12345678、seed 大端、错误字节序返回 7F 27 35、示例 seed 0x1A2E0E7F→key 0x0E91B54D 均一致（已手工复算）。未验证点：PoC 未连接真实服务复跑；原文无版本信息；frontmatter 无 sources/source_url。
---

## 一句话结论

UDS 诊断服务 `0x27 SecurityAccess` 使用“请求 seed → 返回 key”的挑战应答；当 key 算法只是 `seed ^ 0xA5A5A5A5`、循环左移 3 位、再加 `0x12345678` 这类可逆运算时，攻击者拿到 seed 即可离线算出 key，通过安全访问并读取后续受保护数据。

## 原理

- UDS `0x27` 流程：发送 `27 01` 请求 seed，服务端返回 `67 01 <4 字节 seed>`；客户端计算 key，发送 `27 02 <4 字节 key>`；服务端验证通过后解锁受保护服务。
- 示例算法：`key = seed ^ 0xA5A5A5A5`；`key = ROL32(key, 3)`；`key = (key + 0x12345678) & 0xFFFFFFFF`。三步都是可逆的，且没有秘密参与，因此 key 完全由公开 seed 决定。
- 字节序是常见坑：seed 按大端解析、key 按大端发送；若按小端处理，服务端返回否定响应 `7F 27 35`（invalidKey）。
- 该攻击不需要破解密码学，只需要从固件/流量/逆向中恢复算法；一旦算法公开，任何 seed 都能通过。
- 变体：算法可能包含查表、CRC、AES/HMAC（若使用固定密钥则仍可恢复）、多级 seed（level 2 使用不同算法/密钥）。

## 触发条件

- 目标暴露 UDS `0x27` 服务（CAN/DoIP/串口/网络网关）。
- seed 长度固定（常见 4/8 字节），key 算法在固件中可逆或密钥硬编码。
- 攻击者能发送诊断请求并读取响应（如通过网关、OBD、调试口）。
- 服务端没有尝试次数限制/锁定，或限制可绕过。

## 利用步骤

1. 连接目标，发送 `27 01`，解析 `67 01` 后的 seed（注意大端）。
2. 从固件/逆向中恢复 key 算法；若未知，抓取多组 seed-key 对做差分分析。
3. 用算法计算 key，按大端拆成 4 字节。
4. 发送 `27 02 <key>`；检查响应是否为 `67 02`（正响应）而非 `7F 27 35`。
5. 解锁后调用受保护服务（如 `0x2E` 写数据、`0x31` 例程、读取 flag/密钥）。
6. 若 level 2 使用不同算法，重复上述过程。

## PoC

```python
import socket
import re

HOST = "target"
PORT = 43593

def calculate_key(seed: int) -> int:
    key = seed ^ 0xA5A5A5A5
    key = ((key << 3) | (key >> 29)) & 0xFFFFFFFF
    key = (key + 0x12345678) & 0xFFFFFFFF
    return key

def recv_some(sock):
    sock.settimeout(1)
    data = b""
    try:
        while True:
            part = sock.recv(4096)
            if not part:
                break
            data += part
            if len(part) < 4096:
                break
    except Exception:
        pass
    return data.decode(errors="ignore")

with socket.create_connection((HOST, PORT), timeout=8) as s:
    print(recv_some(s))
    s.sendall(b"2701\n")
    resp = recv_some(s)
    print(resp)

    m = re.search(r"67 01 ((?:[0-9A-F]{2} ){3}[0-9A-F]{2})", resp)
    seed = int.from_bytes(bytes(int(x, 16) for x in m.group(1).split()), "big")
    key = calculate_key(seed)
    payload = "2702 " + " ".join(f"{b:02X}" for b in key.to_bytes(4, "big")) + "\n"
    s.sendall(payload.encode())
    print(recv_some(s))
```

## 变体与关联

- 变体：key 算法包含查表/CRC/多轮移位；可通过多组 seed-key 对拟合或从固件恢复。
- 变体：level 2 使用不同 seed 长度/算法/密钥；需要分别分析。
- 变体：seed 由弱 PRNG 生成，可预测下一个 seed 或重放。
- 关联：[[ctf-reverse-go-paper-bin-rc4-custom-xxtea-multilayer]]（自定义加密逆推）、[[crypto-prng-lcg-parameter-recovery-delta-gcd]]（弱 PRNG）、[[crypto-protocol-identity-field-spoofing-missing-sender-auth]]（协议认证缺陷）。

## 检测与防御

- 防御：key 算法应使用带秘密的 HMAC/AES（密钥存放在安全硬件/HSM），不要用纯公开变换。
- 防御：限制 `0x27` 尝试次数、失败锁定、按会话/诊断仪认证；seed 使用 CSPRNG 并一次性有效。
- 检测：短时间内大量 `27 01/27 02` 请求、同一 seed 重复、失败响应 `7F 27 35` 激增。
- 响应：确认弱 seed-key 后轮换诊断密钥，限制诊断接口暴露面，审计受保护服务的访问记录。
