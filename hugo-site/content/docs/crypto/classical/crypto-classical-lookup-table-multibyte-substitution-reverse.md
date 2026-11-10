---
id: crypto-classical-lookup-table-multibyte-substitution-reverse
title: 打表替换（汉字映射表）加密只是单表替换：按编码单位切分后查逆表即可还原，多字节映射还需按 3 字节分组
type: scenario
domain: crypto
path: crypto/classical
technique: classical-lookup-table-multibyte-substitution-reverse
tags:
- crypto
- classical
- substitution
- lookup-table
- multibyte
- ctf
cve: []
severity: info
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-W1
  verified_at: '2026-11-08T11:48:07+08:00'
  notes: 已对照原文核对：原文「三·理解」的 englishToChinese 表（'a'→阿 'b'→博 … ' '→空格）、加密逐字符查表、解密端用 (unsigned char)c >= 0x80 累积到 3 字节再查逆表、未映射字符原样保留，以及“打表加密本质属单表替换、安全性低”的自评均一致；原文 `Hello World! This is a test.` → `海恩兰兰欧 威欧荣兰达! 天海爱山 爱山 阿 天恩山天.` 的示例也与卡内描述相符。核对时补一条原文存在的细节：表里小写 o 与大写 O 都映射为「欧」，建逆表时会互相覆盖、大小写不可区分，已在原理与 PoC 注明。未验证点：未在本机编译复跑原文 C++ 代码；表外字符/emoji 的 4 字节分组属卡片延伸。
url: /docs/crypto/classical/crypto-classical-lookup-table-multibyte-substitution-reverse/
draft: false
kb_aliases:
- 打表加密
- 汉字映射表
- 查表替换
- 多字节替换表
- 自定义映射表加密
---

## 一句话结论

把每个英文字母按一张固定表换成汉字（或任意符号）得到的“加密文本”，本质仍是**单表替换**：只要拿到（或推测出）正向表就能建逆表逐单位还原；实现上要注意映射单位是**多字节 UTF-8 字符**而不是单字节，解密必须按 3 字节边界分组再查表，否则逆表永远查不中。

## 原理

- **映射表就是密钥**：`{'a':"阿", 'b':"博", ...}` 是一张 26 个字母（大小写各一套）加空格的查表；加密是 `查表(明文字符)`，解密是 `逆表(密文单位)`。密钥空间等于表的排列组合，但对已知表或可猜表（如姓氏/百家姓顺序）几乎没有强度。注意它**不是严格意义上的单射置换**：原文表里小写 `o` 与大写 `O` 都映射到同一个「欧」，建逆表时后者会覆盖前者（或随遍历顺序决定），这两个字在密文里不可区分——这正是打表替换连“大小写”这一位信息都可能丢掉的实例。
- **为什么多字节要按单位分组**：UTF-8 下一个汉字是 3 字节，`for (char c : input)` 逐字节遍历时，一个汉字会被拆成 3 个“字符”，逐字节查逆表必然失败；正确做法是用 `(unsigned char)c >= 0x80` 判断进入多字节缓冲、累计到 3 字节后整块查表再清空缓冲。
- **为什么加密端可以逐字节**：加密端遍历的是**明文字母**（ASCII，单字节），每字符查一次正向表并输出一个汉字串，天然对齐；不对称点只在解密端，所以这类自实现代码最常见的 bug 就是解密失败/输出乱码。
- **安全性等价于凯撒之上的一层**：单表替换对频率分析/已知明文攻击不设防；若表内容完全未知，用“中文常用姓氏表”“百家姓顺序”这类字典做候选搜索，或直接对已知明文（flag 前缀）做已知明文攻击即可定表。
- **识别信号**：密文里出现大量中文字符且长度是明文的整数倍（本例每个字母换一个汉字，长度约 3 倍字节数）；把汉字按 3 字节切开后词频仍符合英文分布。若明文同时含大小写同形（如 `o`/`O` 同表项），还原出来的大小写可能与原文不符，需回代验证。

## 触发条件

- 密文由固定表替换后的多字节字符（汉字、emoji、符号串）组成，且替换是逐字符一致的。
- 能拿到正向表（源码、出题附件）、或能用已知明文（`flag{`/`ictf{` 前缀）反推部分映射。
- 明文为 ASCII 字母/数字（映射表的键集合有限）。
- 解密实现按编码单位分组（否则需要先修实现）。

## 利用步骤

1. 判断单位：统计密文字节长度与可见字符数，若“字符数 = 明文字母数”且每字符 3 字节（UTF-8 汉字），按 3 字节切分。
2. 建逆表：`reverse[value] = key` 遍历正向表；若只有密文没有表，先用已知前缀（如 `ictf{`）反推前几个映射，再用词典/姓氏表补全。
3. 逐单位还原：把密文按 3 字节分组，逐组查逆表，命中则输出对应 ASCII 字符，未命中保留原单位（对应加密端“未定义字符直接保留”的行为）。建表时若发现多个明文字符映射到同一密文（如 `o`/`O` 同为「欧」），要显式处理覆盖关系，否则大小写会丢。
4. 校验：把还原结果再正向加密一遍，应得到原密文；或检查是否符合英文/flag 格式。
5. 若结果是混合文本（中文夹英文），说明表只覆盖部分字符，按“未映射字符保留”规则处理即可。

## PoC

```cpp
// 解密侧的正确写法：按 UTF-8 多字节单位分组后再查逆表
std::unordered_map<std::string, char> reverseKey;
for (auto &p : englishToChinese) reverseKey[p.second] = p.first;
// 注意：原文表里 'o' 与 'O' 同为「欧」，上面这句会让后者覆盖前者，
// 逆表无法区分大小写；需要时改为 multimap 或按上下文补判。

std::string out, buf;
for (char c : input) {
    if ((unsigned char)c >= 0x80) {          // 多字节字符的第一/后续字节
        buf += c;
        if (buf.size() == 3) {                // 一个汉字 = 3 字节
            auto it = reverseKey.find(buf);
            out += (it != reverseKey.end()) ? it->second : buf;  // 未定义则保留
            buf.clear();
        }
    } else {
        out += c;                            // ASCII 原样保留
    }
}
```

```python
# 若表已知，Python 侧更简单：按字符（而非字节）分组
rev = {v: k for k, v in table.items()}
plain = ''.join(rev.get(ch, ch) for ch in cipher)
```

## 变体与关联

- 变体：表里同一明文对应多个密文（同义替换表）时属于多表替换，频率分析被削弱，需要按位置/上下文推断，强度略高于单表但仍远不及现代密码。
- 变体：替换单位是 emoji/私有区字符，思路不变，只是分组长度按 UTF-8 变化（emoji 常为 4 字节）。
- 变体：如果把两套表叠加使用（A 表加密后用 B 表再加密），仍是单表替换的复合，逆序用两张逆表即可还原，不增加实质强度。
- 关联：[[crypto-classical-monoalphabetic-substitution-frequency-tool]]（纯字母单表替换的频率分析）、[[crypto-classical-column-transpose-vertical-read-caesar-shift]]（换位类）、[[crypto-classical-pigpen-variant-fence-column-decode]]（符号表替换）。

## 检测与防御

- 教学/CTF 场景：映射表替换不提供任何机密性，知道表即等于知道明文；真实系统不应使用。
- 若遗留代码用“字符表”做数据脱敏/编码：检测信号是固定映射、无随机化、无完整性校验；应改为标准编码（如 Base64 仅作编码）或 AEAD 加密。
- 实现层面：解密端必须按编码单位分组，且需处理“未映射字符保留”的一致性，否则会出现“加密成功、解密乱码”的经典 bug。
