---
id: crypto-rsa-bleichenbacher-pkcs1v15-padding-oracle
title: Bleichenbacher PKCS#1 v1.5 填充预言机：反复查询逐位恢复 RSA 明文
type: scenario
domain: crypto
path: crypto/rsa
technique: rsa-bleichenbacher-padding-oracle
tags:
- rsa
- padding-oracle
- pkcs1-v1_5
- bleichenbacher
- chosen-ciphertext
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V127
  verified_at: '2026-11-06T04:10:33+08:00'
  notes: 已对照原文核对：原文仅给出 socket 桥接脚本（从 crypto-attacks 导入 attack），卡片如实标注核心区间算法在外部实现、oracle 极性需按题目调整，未夸大为完整 PoC；PKCS#1 v1.5 格式 00 02||PS||00||M、B=2^{8(k-2)}、合法区间 [2B,3B) 正确。未验证点：未端到端复跑；原文无受影响版本；frontmatter 无 sources/source_url。
url: /docs/crypto/rsa/crypto-rsa-bleichenbacher-pkcs1v15-padding-oracle/
draft: false
kb_aliases:
- Bleichenbacher 攻击
- PKCS#1 v1.5 填充预言机
- RSA padding oracle
- million message attack
- 选择密文攻击
---

## 一句话结论

当服务端按 PKCS#1 v1.5 解密 RSA 密文，并把“填充是否合法”通过错误信息、状态码或响应时间暴露出来时，攻击者可以构造 `c' = c·s^e mod n` 反复查询，利用合法填充对应的明文区间约束不断收缩，最终恢复原始明文，无需私钥。

## 原理

- PKCS#1 v1.5 加密块格式为 `00 02 || PS || 00 || M`，`PS` 至少 8 个非零字节。解密后若前两字节不是 `00 02`，就是填充错误。
- 设模数字节长度为 `k`，`B = 2^{8(k-2)}`。合法填充意味着解密整数 `m'` 落在 `[2B, 3B-1]` 区间内。
- 攻击者提交 `c' = c·s^e mod n`，服务端解密得到 `m' = m·s mod n`。查询结果只告诉攻击者“`m·s mod n` 是否落在 `[2B,3B)`”，这是一个关于 `m` 的区间约束。
- 选择不同的 `s`（初始时让 `s` 递增，随后用区间边界计算候选 `s`），把每次查询得到的约束与已有区间求交，`m` 的可能范围迅速缩小；当区间只剩一个整数时即恢复 `m`。
- 该攻击是选择密文攻击：攻击者不需要私钥，只需要一个能区分填充合法/非法的“预言机”。原始论文的查询量约为百万级（`2^20` 量级），优化变体可显著减少。
- 如果服务端对填充错误返回统一错误但响应时间不同，或先检查长度再检查填充，也可能构成计时/行为预言机。

## 触发条件

- 服务端提供 RSA PKCS#1 v1.5 解密接口，并把填充合法性以可区分的方式返回（错误文案、状态码、连接断开、耗时差异等）。
- 攻击者已知公钥 `(n,e)` 和目标密文 `c`，并能大量提交任意密文。
- 没有完整性保护或速率限制；同一密文可重复查询。
- 典型场景：旧版 TLS RSA 密钥交换、邮件客户端、自定义“解密并返回是否成功”的接口。

## 利用步骤

1. 从公钥文件提取 `n`、`e`，确认服务端使用 PKCS#1 v1.5 填充。
2. 实现 `padding_oracle(c_int)`：连接服务端、发送 `long_to_bytes(c_int, k)`、按回显判断填充是否合法；超时/连接重置也要按题目逻辑归类。
3. 调用 Bleichenbacher 攻击实现（如 crypto-attacks 的 `bleichenbacher_attack.attack(padding_oracle, N, E, C)`），由攻击代码选择 `s` 并维护区间。
4. 攻击返回明文整数后转字节；按 `00` 分隔去掉填充，提取消息/flag。
5. 若查询失败，检查 oracle 判断是否与题目返回一致、发送格式（hex/原始字节/换行）是否正确、是否有查询频率限制。

## PoC

```python
import socket
import logging
from Crypto.Util.number import bytes_to_long, long_to_bytes
from bleichenbacher_attack import attack   # crypto-attacks 项目实现

logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')

TARGET_IP = "127.0.0.1"
TARGET_PORT = 1337
N = 0x...
E = 65537
C_INT = int("abcdef123456...", 16)

def padding_oracle(c_int):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2.0)
        s.connect((TARGET_IP, TARGET_PORT))
        k = (N.bit_length() + 7) // 8
        payload = long_to_bytes(c_int, k)
        s.sendall(payload + b"\n")
        response = s.recv(1024)
        s.close()
        # 按题目实际返回调整：合法填充返回 True
        return b"Invalid" not in response
    except (socket.timeout, ConnectionResetError):
        return False

m_int = attack(padding_oracle, N, E, C_INT)
m_bytes = long_to_bytes(m_int)
print(m_bytes.hex())
if b"\x00" in m_bytes:
    print(m_bytes.split(b"\x00")[-1])
```

> 说明：核心区间收缩算法在 `bleichenbacher_attack.attack` 中，原文只给出交互桥接脚本；oracle 的 True/False 极性必须与题目返回严格一致。

## 变体与关联

- 变体：服务端只返回“解密成功/失败”而不区分具体错误，仍可能构成预言机；统一错误文案但耗时不同则转为计时攻击。
- 变体：PKCS#1 v1.5 签名验证的填充错误也可能构成 Bleichenbacher 类签名伪造（如 ROBOT 类问题）。
- 变体：RSA-OAEP 的首字节检查对应 Manger 攻击，数学与查询方式不同。
- 关联：[[crypto-rsa-manger-oaep-first-byte-oracle]]（OAEP 首字节零预言机）、[[crypto-rsa-lsb-parity-oracle]]（奇偶预言机）、[[crypto-aes-cbc-padding-oracle-certificate-service]]（对称加密 padding oracle 的同类思路）。

## 检测与防御

- 防御：不要向外部暴露 RSA 解密预言机；解密失败统一返回同一错误、同一状态码、尽量恒定时间。
- 防御：新系统使用 RSA-OAEP；TLS 使用 ECDHE 等前向安全密钥交换，禁用 RSA 密钥交换。
- 防御：加入速率限制、查询审计与异常检测；对同一密文的重复提交进行告警。
- 检测：日志中出现大量格式异常或重复的 RSA 密文、同一来源高频调用解密接口、响应长度/耗时分布异常。
- 响应：确认预言机存在后立即下线相关接口或改为 OAEP，轮换密钥并审计历史解密请求。
