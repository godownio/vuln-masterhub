---
id: code-analysis-reverse-obfuscation-huffman-tree-bitstring-string-decode
title: Huffman 式字符串混淆：frequency/left/right 树 + 0/1 位串 + Crypto++ Base64 的识别与还原
type: scenario
domain: code-analysis
path: code-analysis/reverse/obfuscation
technique: huffman-tree-bitstring-string-obfuscation
aliases:
- Huffman 字符串加密
- frequency left right 树
- 二进制位串编码字符串
- 字符频率树混淆
- CryptoPP Base64Decoder 字符串
- 红队样本字符串解密
tags:
- reverse
- obfuscation
- string-encryption
- huffman
- base64
- cryptopp
- malware-analysis
- windows
cve: []
severity: low
confidence: medium
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V382
  verified_at: '2026-11-09T09:00:31+08:00'
  notes: 已对照原文全文与 34/34 截图核对：img12-14/22-25 调试器内存中可见 {"frequency":…,"left":…} 嵌套 JSON 树、img11/25-26 可见仅含 ASCII 0/1 的长位串(memcpy a00110111000101, 0x2D38)、img17 可见 CryptoPP::Base64Decoder/StringSinkTemplate 虚表构造，img12-13/22-24 可见夹带的 Base64 样式串与运行时还原出的 OSS URL；卡片按证据归纳为频率树+位串+Huffman 式解码，属对原文未展开算法的合理推断(卡片 confidence medium 且正文注明字段名需按样本调整)。原文未给版本，已 clear。
  unverified:
  - 截图中 JSON 只直接可见 frequency/left 键，right 键系按二叉树结构与 Huffman 语义推断(左子树较长时 right 出现在字符串后段，未被截图完整展示)；Crypto++ Base64Decoder 用于树/位串还是下载载荷的判定同为邻近代码推断，需动态跟踪确认。
---

## 一句话结论

样本把字符串/URL 用一棵以 JSON `{"frequency":…,"left":…,"right":…}` 序列化的字符频率树（Huffman 式）加一段只含 `0`/`1` 的位串编码存储，运行时用 Crypto++ 的 `Base64Decoder`/`StringSink` 解码并按位串在树中左右行走还原明文；静态看到长位串、`frequency/left/right` JSON 和 CryptoPP 虚表即可判定此类混淆，动态在解码函数返回处下断可直接 dump 明文（如 OSS URL、C2 配置）。

## 原理

- **Huffman 式编码**：对字符按出现频率构建二叉树，频率低的字符路径长、频率高的路径短；每个字符对应一条由 0/1 组成的路径，整段文本变成位串，长度通常短于原文的固定宽度编码。树节点常用 `frequency`（权重）、`left`/`right`（子节点）表示。
- **样本中的证据**：
  - 内存/调试器中出现 JSON 形态的树：`{"frequency": 128, "left": {"frequency": 57, "left": {"frequency": 25, ...}}, ...}`；
  - 静态数据里有只含 ASCII `0`/`1` 的长位串（如 `00110111000101...`，长度可达数千字节）；
  - 代码引用 `CryptoPP::Base64Decoder`、`CryptoPP::StringSinkTemplate<std::string>` 的虚表，说明用 Crypto++ 做 Base64 解码后把结果写入 `std::string`；
  - 运行时解码函数返回后，调试器可直接看到明文 URL（如阿里云 OSS 的 `.jpg`/`.txt` 地址）。
- **可能的组合方式**：树以 JSON/字符串形式存储（可能再经 Base64），位串是待解码文本；解码器先还原树，再按位串逐位走树（0 走左、1 走右），到达叶节点输出字符。样本还可能用一个短 key（如 `N0n-FJTiMJa871z`）参与树/位串的解密或校验；具体顺序需按样本反汇编确认。
- **为什么用这种混淆**：位串没有固定字节模式、字符串不以明文出现，简单的 `strings`/YARA 明文规则失效；树结构是数据相关的，无法用固定 XOR 密钥一把梭；比逐字符 XOR 更难自动化还原。
- **识别要点**：不要只搜 URL 明文；先找 `frequency`/`left`/`right` JSON 与长 `0`/`1` 串，再找 `Base64Decoder` 引用与解码函数调用点，最后在解码输出处下断。
- **局限**：树和位串都是数据，动态执行时必然在内存中还原为明文；hook 解码函数或断点 dump 即可绕过；若样本对树/位串再做一层加密，需要先定位并还原该层（key 可能在字符串常量或参数中）。

## 触发条件

- 目标为 Windows PE/loader，静态字符串中大量不可读数据，但有 `frequency`/`left`/`right` JSON、长 `0`/`1` 位串或 Crypto++ `Base64Decoder` 引用。
- 样本运行时会解密 URL/配置/命令等字符串；可在调试器中跟踪到解码函数。
- 分析者能使用 IDA/x64dbg 与 Python 重写解码逻辑，或直接在解码返回处 dump。
- 若是离线还原，需要完整的树数据与位串（以及可能的 key）。

## 利用步骤

1. 静态扫描：搜索字符串 `"frequency"`、`"left"`、`"right"`、长 `0`/`1` 串、`CryptoPP`/`Base64Decoder`/`StringSink` 相关符号或虚表引用。
2. 定位解码函数：从 `Base64Decoder` 虚表交叉引用或位串/树数据的引用点回溯，找到负责构建树并遍历位串的函数。
3. 动态验证：在解码函数返回处下断，查看返回的 `std::string`/缓冲区，确认是否为 URL、JSON 或命令；记录树、位串与 key 的关系。
4. 离线还原：按样本逻辑实现 Huffman 解码（解析树 JSON、逐位走树），或直接保存 dump 的明文。
5. 若树/位串还有一层加密，先定位解密函数（key 可能在参数或字符串常量），还原后再做 Huffman 解码。
6. 把还原出的 URL/配置与网络行为对照，确认解码正确；对同族样本复用一个脚本批量处理。

## PoC

识别与动态 dump 思路（不是完整样本算法）：

```python
# 1) 静态特征：树 JSON + 位串
#    b'{"frequency": 128, "left": {"frequency": 57, ...'
#    b'00110111000101...'（仅 ASCII '0'/'1'）

# 2) 若已从内存/文件提取出树（dict）与位串，按 0=left / 1=right 走树：
def decode_huffman(tree, bits):
    out, node = [], tree
    for b in bits:
        node = node['left'] if b == '0' else node['right']
        if 'char' in node:          # 叶节点（样本可能用 value/符号字段）
            out.append(node['char'])
            node = tree
    return ''.join(out)

# 3) 动态更快：在解码函数返回处下断，直接读取返回的 std::string
#    x64dbg: bp <decode_func+ret>; 运行后 dump [rax] / std::string 缓冲区
```

说明：原文通过调试器在解码函数返回处直接看到 `{"frequency":...}` 树与明文 OSS URL，未给出完整的树/位串算法；本卡按证据给出识别与还原方法，具体字段名（叶节点字符/值）需按样本调整。

## 变体与关联

- **变体**：树可用数组/扁平化序列化（而非 JSON）；位串可先 Base64 再解码；字符表可用索引代替叶节点字符；key 可参与树节点权重或位串异或。
- **变体**：同类“数据相关编码”还有算术编码、区间编码、字典压缩（LZ）等；识别信号都是“无固定字节模式的紧凑数据 + 运行时解码函数”。
- **关联**：[[code-analysis-reverse-obfuscation-xor-charcode-js-kit-static-regex-deobfuscation]]（固定 XOR 字符编码的静态还原，复杂度更低）、[[code-analysis-reverse-obfuscation-grandoreiro-string-decryption-triple-base64-diff-xor-aes]]（多层 Base64/XOR/AES 字符串解密）、[[code-analysis-reverse-obfuscation-rust-chacha20poly1305-string-decrypt-idapython]]（IDAPython 批量还原字符串）。
- **边界**：若样本在解码后立即使用并清零缓冲区，需在解码返回瞬间 dump；若树/位串被分片存储或运行时重建，静态提取不完整，需动态跟踪。

## 检测与防御

- 这是逆向/恶意样本分析技术，不产生攻击面。
- 分析侧：优先动态断点 dump，静态只用于确认算法；保存树/位串/key 以便批量还原同族样本；对解码函数做签名（CryptoPP 虚表、树字段字符串）可快速识别同类混淆。
- 检测侧（蓝队）：样本静态数据中出现 `frequency/left/right` 结构、超长 `0`/`1` 串、Crypto++ Base64 解码链，可作为“字符串混淆 loader”的静态特征；运行时监控非模块内存中的明文 URL 生成与随后网络请求的关联。
