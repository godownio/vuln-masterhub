---
id: ai-security-rag-security-blind-rag-matrix-mask-cpa-vector-recovery
title: Blind RAG 矩阵掩码选择明文攻击：单位向量查询恢复文档向量并解密 AES-GCM
type: scenario
domain: ai-security
path: ai-security/rag-security
technique: blind-rag-matrix-mask-cpa
tags:
- rag
- vector-database
- chosen-plaintext
- linear-algebra
- matrix-mask
- aes-gcm
- oracle
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V115
  verified_at: '2026-11-06T01:56:23+08:00'
  notes: 已对照原文 §Blind RAG 核对：t1=q*M1^-1/t2=q*M2^-1、c1=v1*M1^T/c2=v2*M2^T、c1·t1+c2·t2=v·q、e_i 查询恢复 v、SHA256(v[i].to_bytes(32,LE))、AES-GCM nonce(12)||ct||tag、flag 均一致；未本机复跑。
url: /docs/ai-security/rag-security/ai-security-rag-security-blind-rag-matrix-mask-cpa-vector-recovery/
draft: false
kb_aliases:
- Blind RAG
- 矩阵掩码 CPA
- 向量数据库选择明文
- c1·t1 + c2·t2 = v·q
- 单位向量恢复向量
- RAG 向量加密攻击
---

## 一句话结论

服务端把查询向量 `q` 分别乘以 `M1^-1`、`M2^-1` 返回 `t1/t2`，而文档向量密文是 `c1=v1*M1^T`、`c2=v2*M2^T`，两者内积满足 `c1·t1 + c2·t2 = v·q`；攻击者只需发送单位向量 `q=e_i`，就能逐坐标读出每篇文档的明文向量 `v[i]`，再按公开的 SHA256 派生规则重建 AES-GCM 密钥并解密文档。

## 原理

- 线性掩码的可组合性：`c1·t1 + c2·t2 = (v1*M1^T)·(q*M1^-1) + (v2*M2^T)·(q*M2^-1) = v1·q + v2·q = (v1+v2)·q`。掩码矩阵在双线性配对中抵消。
- 因此服务端实际上提供了一个“向量内积 oracle”：对任意 `q` 返回 `v·q`。取 `q = e_i`（第 i 个分量为 1，其余 0）即可得到 `v[i]`。
- 文档加密 key 的派生方式公开：`key = SHA256(v[0].to_bytes(32, LE) || ... || v[63].to_bytes(32, LE))`；恢复完整 64 维向量后即可重建 key。
- 文档密文是 AES-GCM：`nonce || ciphertext || tag`；用重建的 key 和 nonce 解密并校验 tag，即可确认恢复正确。
- 这个攻击不需要破解矩阵或 AES，只需要利用“查询 oracle 返回线性变换结果”这一设计缺陷；64 次查询即可恢复一篇文档的完整向量。

## 触发条件

- RAG/向量检索服务允许攻击者提交任意查询向量，并返回经过线性变换的查询结果（`t1/t2`）或内积分数。
- 文档向量使用可逆线性掩码加密，且掩码矩阵固定/可预测；服务端不限制查询次数或不做查询隐私保护。
- 文档 key 由向量本身确定性派生，或攻击者能获得 key 派生规则。
- 攻击者可获取文档密文（如 `/database` 接口返回 `c_v`、`c_d`）。

## 利用步骤

1. 获取 `/database` 返回的 `p`、`n`、每篇文档的 `c_v=[c1,c2]`、`c_d`、`label`。
2. 对 `i = 0..n-1` 构造 `q = e_i`，调用 `/query` 得到 `t_q=[t1,t2]`。
3. 对每篇文档计算 `v[i] = (c1·t1 + c2·t2) mod p`，得到完整 `v`。
4. 按 `key = SHA256(concat(v[i].to_bytes(32, "little")))` 派生 key。
5. 解析 `c_d` 为 `nonce(12) || ciphertext || tag(16)`，用 AES-GCM 解密并验证 tag。
6. 输出明文，按 label/flag 格式筛选目标文档。

## PoC

```python
import hashlib, json, urllib.request
from Crypto.Cipher import AES

BASE = "https://target"
def get_database():
    return json.load(urllib.request.urlopen(BASE + "/database"))

def post_query(q):
    body = json.dumps({"q": [str(x) for x in q]}).encode()
    req = urllib.request.Request(BASE + "/query", data=body,
        headers={"Content-Type": "application/json"}, method="POST")
    data = json.load(urllib.request.urlopen(req))
    return [[int(x) for x in part] for part in data["t_q"]]

def dot(a, b, p):
    return sum(int(x) * int(y) for x, y in zip(a, b)) % p

def derive_key(v):
    material = b"".join((x % (1 << 256)).to_bytes(32, "little") for x in v)
    return hashlib.sha256(material).digest()

challenge = get_database()
p, n = int(challenge["p"]), int(challenge["n"])

basis = []
for i in range(n):
    q = [0] * n
    q[i] = 1
    basis.append(post_query(q))

for doc in challenge["database"]:
    c1 = [int(x) for x in doc["c_v"][0]]
    c2 = [int(x) for x in doc["c_v"][1]]
    v = [(dot(c1, t1, p) + dot(c2, t2, p)) % p for t1, t2 in basis]
    blob = bytes.fromhex(doc["c_d"])
    nonce, ct, tag = blob[:12], blob[12:-16], blob[-16:]
    pt = AES.new(derive_key(v), AES.MODE_GCM, nonce=nonce).decrypt_and_verify(ct, tag)
    if doc.get("label") == "flag" or b"flag{" in pt:
        print(pt.decode())
```

案例输出：`flag{v3ct0r_bl1nd_r4g_cpa_m4tr1x_r3c0v3ry}`。

## 变体与关联

- 变体：服务端只返回内积分数而不是 `t1/t2` 时，可直接把分数当 oracle，同样用 `e_i` 查询读取 `v[i]`。
- 变体：查询向量会被归一化时，先选一个已知锚点，再用微扰法恢复（见 LeakyRAG 卡）。
- 变体：掩码矩阵随请求变化但仍可逆且客户端已知时，仍可构造消去；若掩码是非线性的，则需要其他攻击。
- 关联：[[ai-security-rag-security-leaky-score-oracle-embedding-reconstruction]]（分数 oracle 版本）、[[ai-security-rag-security-embedding-inversion-leaked-vector-store]]（泄露向量库反演）、[[ai-security-rag-security-chromadb-unauth-knowledge-base-poisoning]]（向量库未授权）。

## 检测与防御

- 防御：不要向不可信客户端暴露线性查询 oracle；对查询做安全多方计算/同态加密时确保不泄露中间掩码结果。
- 防御：文档 key 不要由向量确定性派生；使用独立随机 DEK 并用 KMS 封装。
- 防御：限制查询次数、加入查询隐私噪声（差分隐私）、对异常单位向量/批量查询告警。
- 检测：短时间内大量 `q=e_i` 或稀疏查询、`/query` 调用次数接近维度、同一来源遍历所有坐标。
- 响应：发现向量泄露后轮换文档密钥、重建向量库、审计查询日志并限制 oracle 访问。
