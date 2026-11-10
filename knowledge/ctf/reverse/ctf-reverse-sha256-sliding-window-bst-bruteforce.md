---
id: ctf-reverse-sha256-sliding-window-bst-bruteforce
title: SHA256 三字节滑动窗口 + 二叉搜索树乱序密文的逆向：3 字符爆破与 2 字节重叠链还原 flag
type: scenario
domain: ctf
path: ctf/reverse
technique: sha256-3byte-sliding-window-bst-bruteforce
aliases:
- SHA256 滑动窗口加密
- 三字节爆破
- 二叉搜索树乱序密文
- BST 密文排序
- 2 字节重叠链
- 巅峰极客2024 Rev
tags:
- ctf
- reverse
- sha256
- sliding-window
- bst
- brute-force
- overlap-chain
- windows
- bcrypt
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V276
  verified_at: '2026-11-07T23:25:20+08:00'
  notes: 已对照原文与 31 张图核对：3 字节滑动窗口 BufferedReader SHA256(BCrypt) + 32 字节循环 XOR、1280 字节 crypt memcmp(0x500)、字符白名单（img16/17：数字/小写/'{'/'-'/'}'，已修正卡片漏写 '{' 并把 62^3 改为 39^3）、BST/有序链表乱序、fla 起始 2 字节重叠链、最终 flag{194a39a4-7937-48fb-bfea-80bd17729f8a}（img29）均一致。卡片保留二进制两轮 16 字节 XOR 与原文等价爆破函数的差异说明。
---

## 一句话结论

程序对输入字符串的每个 3 字节滑动窗口（步长 1）计算 SHA256，把 32 字节摘要与窗口明文做循环异或得到 32 字节密文块；所有窗口的密文块按二叉搜索树/有序链表的顺序（小值在前、大值在后）拼接成 1280 字节，与硬编码 `crypt` 比较。SHA256 无法直接逆，但输入字符被限制在数字、小写字母、`{`、`-`、`}` 的小字符集内，3 字节空间仅约 39^3；攻击者枚举所有 3 字符组合、用同样的 SHA256+XOR 算法生成 32 字节块，在 40 个密文块中查表得到对应的 3 字符，再按“当前组前 2 字节 = 上一组后 2 字节”的重叠关系从 `fla` 开始链式拼接，即可恢复 42 字符 flag。

## 原理

- **输入约束**：程序校验每个输入字符满足 `(c-'0')<=9 || (c-'a')<=0x1A || c=='-' || c=='}'`，即数字、小写字母、`{`（0x7B 落在 `c-'a'<=0x1A` 内）、`-`、`}`，共 39 个字符；这使 3 字节窗口的搜索空间仅 39^3 ≈ 5.9 万（原文脚本按大小写+符号枚举也只约 65^3），可全量爆破。
- **滑动窗口哈希**：对 `i=0..len-3`，取 `str = input[i:i+3]`；用 Windows BCrypt（`BCryptOpenAlgorithmProvider("SHA256")`、`BCryptHashData`、`BCryptFinishHash`）得到 32 字节 `pbHash`；再把 `pbHash` 与 3 字节明文循环异或，得到 32 字节密文块。原文还原的等价算法为：
  ```python
  def encrypt(data):            # data 是 3 字符
      h = hashlib.sha256(data.encode()).digest()
      return bytes(h[i] ^ data.encode()[i % len(data)] for i in range(32))
  ```
  （二进制中还有两轮 16 字节的 XOR/掩码细节，反编译代码头尾参差；原文以该等价函数爆破成功。）
- **1280 字节 = 40 块**：`Buf1[1]-Buf1[0] == 1280` 且 `memcmp(Buf1[0], &crypt, 0x500)`；每块 32 字节，共 40 个滑动窗口，因此 flag 长度为 42（40 个窗口 + 2）。
- **BST/有序链表乱序**：程序把新生成的 32 字节哈希与已有密文比较，按“小的放前面、大的放后面”插入 `std::list`/二叉搜索树（反编译中可见 `v26 = *v26`/`v26 = v26[2]` 的左右子树遍历、`memcmp` 比较、`while(!*(v26+25))` 等特征）。最终 `result` 是按 BST 顺序拼接的密文，不是输入顺序；因此不能按位置爆破，只能按“块内容”匹配。
- **3 字符爆破 + 查表**：枚举 charset 的所有 3 字符组合，计算 32 字节密文并转 hex；把 40 个密文块切成 64 hex 字符一段，用 `enc_list.index(enc_result)` 找到匹配的块，记录对应的 3 字符。由于 40 个窗口两两重叠（相邻窗口共享 2 字节），这些 3 字符组本身构成一条链。
- **2 字节重叠链拼接**：从已知起始组 `fla`（flag 开头）开始，找第一个组的后 2 字节等于下一组前 2 字节的 3 字符组，追加第三字符；重复直到拼出 42 字符。原文最终得到 `flag{194a39a4-7937-48fb-bfea-80bd17729f8a}`。
- **为什么成立**：SHA256 虽不可逆，但窗口只有 3 字节且字符集受限，暴力枚举可行；BST 只改变顺序不改变内容，按块内容匹配即可绕过；相邻窗口重叠 2 字节提供了天然的拼接顺序。

## 触发条件

- CTF Reverse 题目：输入经过“短窗口哈希 + XOR”加密，密文块数量有限（如 40 块×32 字节），且输入字符集受限（可枚举 3 字符组合）。
- 程序把密文块按 BST/有序结构重排，导致密文顺序与明文顺序不一致；但块内容可通过重新计算匹配。
- 已知或可猜出起始 3 字符（如 `fla`/`flag` 前缀），用于启动链式拼接。
- 有可用的 SHA256 实现与足够算力（几十万次哈希在普通机器上秒级完成）。

## 利用步骤

1. 逆向后确认：输入长度约 42、每 3 字节滑动窗口、SHA256 + XOR、密文 1280 字节（40×32）、字符集为数字/小写/`-`/`}`。
2. 从二进制中导出 1280 字节 `crypt`，按 64 hex 字符切成 40 个块，保存为 `enc_list`。
3. 实现等价的 `encrypt(3字符)`：`SHA256(窗口)` 后与窗口字节循环异或 32 字节，转大写 hex。
4. 枚举 charset（`1234567890qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM-{}`，实际程序只允许小写/数字/`{`/`-`/`}`（39 字符），可缩小）的所有 3 字符组合；对每个组合计算 `encrypt`，若其 hex 在 `enc_list` 中则记录 `data`。
5. 从 `fla` 开始：找 `data[:2] == current[-2:]` 的组，追加 `data[2]`；重复直到长度为 42。
6. 输出 flag；用二进制或重实现的 `encrypt` 验证每个 3 字节窗口的密文块都存在于 `crypt` 中。

## PoC

原文的 Python 求解脚本（核心逻辑，`enc` 为 1280 字节密文的 hex）：

```python
import hashlib, itertools

enc = "EB74464F..."  # 1280 字节密文 hex，共 40 段
enc_list = [enc[i:i+64] for i in range(0, len(enc), 64)]

def encrypt(data):
    data_bytes = data.encode()
    h = hashlib.sha256(data_bytes).digest()
    return bytes(data_bytes[i % len(data_bytes)] ^ h[i] for i in range(32))

flag_list = []
charset = "1234567890qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM-{}"
for tup in itertools.product(charset, repeat=3):
    data = ''.join(tup)
    if encrypt(data).hex().upper() in enc_list:
        flag_list.append(data)

current = "fla"
i = flag_list.index("fla")
while len(current) < 42:
    if flag_list[i][:2] == current[-2:]:
        current += flag_list[i][2]
        i = 0
    else:
        i += 1

print(current)
# flag{194a39a4-7937-48fb-bfea-80bd17729f8a}
```

> 说明：原文脚本中 `enc` 很长，此处省略；`encrypt` 为原文根据二进制还原的等价函数（二进制还有两轮 16 字节 XOR/掩码细节）。原文最终输出 `flag{194a39a4-7937-48fb-bfea-80bd17729f8a}`；本卡未复跑。

## 变体与关联

- **哈希爆破类**：短输入 + 固定哈希的 CTF 题通常可枚举/字典攻击；本卡的特别点是“滑动窗口 + 重叠链 + BST 乱序”。
- **BST 乱序**：反编译中的左右子树遍历/`memcmp` 比较/有序插入是识别 BST 的特征；如果密文按哈希值排序，按块内容匹配即可，不必还原树。
- **窗口长度变体**：3 字节窗口可用 2 字节重叠链；若窗口为 k 字节，则用 k-1 字节重叠链；字符集越小，爆破越快。
- **加密变体**：SHA256 换成 MD5/SHA1/CRC 等确定性哈希同样可爆破；XOR 可能有多轮/掩码，需按二进制还原等价函数。
- 关联：[[ctf-reverse-dotnet-dnspy-de4dot-arithmetic-inverse]]（另一类逆向中的可逆变换）、[[crypto-hash-length-extension]] 等哈希题；本卡是“不可逆哈希 + 小空间爆破 + 结构重排”的组合。
- 边界：输入字符集过大（如全 ASCII）、窗口长度过大、密文块不足或哈希带随机盐时，爆破/匹配失效。

## 检测与防御

- 该场景为 CTF/授权逆向分析；真实产品不应使用“短窗口 SHA256 + XOR”作为加密/认证，短输入可被字典/暴力枚举，XOR 也不提供完整性。
- 设计侧：使用带盐 KDF/ AEAD（AES-GCM、ChaCha20-Poly1305）保护敏感数据；避免把哈希当作可逆加密；对输入长度/字符集不要形成可枚举的小空间。
- 分析侧：先确认窗口长度、字符集、哈希算法与密文块大小；若密文顺序异常，检查是否按 BST/排序结构存储；用块内容匹配 + 重叠链重建顺序，通常比还原数据结构更直接。
- 检测（防守）：二进制中出现 `BCryptOpenAlgorithmProvider("SHA256")`、固定长度密文比较、3 字节窗口循环与 BST 插入模式时，可判断为 CTF/混淆式校验，而非生产级加密。
