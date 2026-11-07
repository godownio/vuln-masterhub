---
id: code-analysis-reverse-windows-aes-config-capa-xref-key-cyberchef
title: 脱壳样本 AES 配置静态提取：capa 定位 AES 调用链、交叉引用回溯静态密钥并用 CyberChef 解密
type: scenario
domain: code-analysis
path: code-analysis/reverse/windows
technique: malware-aes-config-capa-xref-key
aliases:
- AES 配置提取
- capa 定位 AES
- 交叉引用找密钥
- CyberChef AES 解密
- 恶意样本配置解密
- HackingTeam Soldier 配置
tags:
- reverse
- windows
- malware-analysis
- config-extraction
- aes
- capa
- ida
- xref
- ioc
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V204
  verified_at: '2026-11-07T02:40:55+08:00'
  notes: 已对照原文与 40 张图片核对；capa 命中与 CyberChef AES-CBC 配置解出一致；未在本机复现
---

## 一句话结论

对脱壳后仍以 AES 加密内嵌配置的恶意 PE，先用 capa 命中 AES 实现与常量引用，再沿调用者交叉引用找到“密文指针 + 长度 + 密钥指针”的加密调用点，回溯密钥缓冲区的唯一写入点取得静态 16 字节密钥，即可用 CyberChef/Python 以 AES-CBC（IV 全零）离线解出结构化配置（C2 地址、采集模块开关等）。

## 原理

- 恶意样本常把配置序列化后 AES 加密内嵌，运行时解密使用；capa 通过 AES S-box/常量、加密循环与 API 特征给出候选函数，把分析范围从整个样本缩小到加密调用附近。本例 capa 的 `encrypt data using AES` 规则命中 `sub_498710`、`sub_4996D0`、`sub_49A620`，`reference AES constants` 规则命中 `sub_498710`、`sub_49A620`。
- AES 封装函数的典型参数是（输出指针、密文指针、长度、密钥指针）或其变体；本例最外层 `sub_49F390` 调用 `sub_4A0840(asc_530257, dword_530253, &xmmword_53B558)`：`asc_530257` 指向不可读密文，`dword_530253 = 0x240`（576 字节，16 的倍数），第三参是密钥缓冲区。
- 密钥通常以静态常量存放在 `.data`，由初始化函数拷入全局缓冲区。对密钥缓冲区做交叉引用，若只有一处写（`sub_4B3190+2D: movups xmmword_53B558, xmm0`），读该函数即可看到 `xmmword_53B558 = xmmword_53017A`，即 16 字节静态密钥常量。
- 模式的推断：解密函数按 16 字节分组处理，本例 IV 为全零、使用 CBC 模式；用该组合能解出可读 JSON，字段结构与样本能力（camera/audio/screenshot/url/sync 等）吻合，反向验证了模式与密钥选择正确。
- 字节序陷阱：IDA 的 `xmmword` 常量按大端数值显示，与内存中的小端字节序相反；从 IDA 复制密钥/密文到 CyberChef 时必须使用内存原始字节顺序（Hex 输入），否则解密失败或得到乱码。

## 触发条件

- 已获得可静态分析的样本（原样本或脱壳 dump）；配置为内嵌密文，而非仅从远程拉取。
- IDA + flare-capa 插件，且规则库版本与 flare-capa 一致（否则插件报错）。
- 样本关键解密逻辑未被 VMP 虚拟化；若 AES 函数被虚拟化，capa 可能无法识别，需要行为 dump 或 VM 逆向。
- 密文以指针 + 长度传给加密函数且长度为 16 的倍数；密钥为静态或由固定常量派生，IV 固定或可推断。
- 明文为结构化配置（JSON/二进制），可通过字段名与可打印字符判断解密是否成功。

## 利用步骤

1. 安装 capa IDA 插件：用 IDA 对应的 Python 执行 `pip install flare-capa`，将 `capa_explorer.py` 拷入插件目录；下载与 flare-capa 版本一致的官方规则库。
2. 在 capa explorer 的 Program Analysis 搜索 `AES`，记录命中函数（本例：`sub_498710` 加密特征 3 处，`sub_4996D0`、`sub_49A620` 引用 AES 常量）。
3. 从 AES 函数逐层查看 Up 交叉引用，向调用者回溯：`mw_aes_1` ← `sub_4984E0+3C`；`sub_4996D0` ← `sub_498580+92`；`sub_4984E0` ← `sub_4A0840+37`。优先找参数形如“密文指针 + 长度（+ 密钥）”的调用。
4. 在 `sub_49F390` 定位到 `sub_4A0840((_m128i *)asc_530257, dword_530253, (int)&xmmword_53B558)`；确认 `dword_530253=0x240` 为 16 的倍数、`asc_530257` 处为高熵密文。
5. 对密钥缓冲区 `xmmword_53B558` 查交叉引用，发现唯一写点 `sub_4B3190+2D`；阅读 `sub_4B3190` 可见 `xmmword_53B558 = xmmword_53017A`，密钥来自 `.data` 静态常量。
6. 从 IDA 十六进制视图按内存字节序复制密钥与密文；在 CyberChef 选择 AES Decrypt：Key=Hex、IV=全零 16 字节、Mode=CBC、Input=Hex；或用 Python `Crypto.Cipher.AES` 解密。
7. 解析解出的 JSON 配置，按字段提取 IOC 与能力开关（本例 `sync.host=178.128.215.46`、`sync.repeat=600`，以及 camera/audio/screenshot/photo/file/addressbook/chat/clipboard/device/call/messages/password/keylog/mouse/url 各模块的 enabled/repeat）。

## PoC

```python
# pip install pycryptodome
from Crypto.Cipher import AES

# 从 IDA 的 xmmword_53017A 按内存字节顺序复制（16 字节）；原文截图密钥被截断，此处用占位符
key = bytes.fromhex("00112233445566778899aabbccddeeff")
# 从 asc_530257 复制密文，长度 0x240；原文未给出完整密文
ct = bytes.fromhex("...")

pt = AES.new(key, AES.MODE_CBC, iv=b"\x00" * 16).decrypt(ct)
print(pt.decode("utf-8", "replace"))
```

```text
CyberChef 等价配方：
AES Decrypt
  Key:  Hex（16 字节内存序常量）
  IV:   00000000000000000000000000000000
  Mode: CBC
  Input: Hex（密文，长度 0x240）
```

## 变体与关联

- 变体：若样本使用 AES-ECB 或非零 IV，调整模式/IV；若密钥由 SHA/RC4 等派生，先还原密钥派生函数再解密。
- 变体：无 IDA 时可用 capa CLI（`capa -f pe sample.exe`）筛出 AES 函数，再在 Ghidra/IDA 中手工追交叉引用。
- 关联：[[code-analysis-reverse-windows-remcos-settings-config-extraction]]（资源 + RC4 配置提取）、[[code-analysis-reverse-windows-dridex-c2-table-signature-extraction]]（C2 表静态定位）、[[code-analysis-reverse-obfuscation-cryptapi-sha1-rc4-config-decrypt]]（配置解密）、[[code-analysis-reverse-windows-silverfox-reversed-config-ipdates-info]]（配置还原）。
- 边界：capa 依赖规则与特征，可能漏报自实现或虚拟化的 AES；配置若分段加密或带压缩层，需要先解包再套用本流程。

## 检测与防御

- 检测（静态）：capa 的 AES 规则命中、`.data` 中高熵常量、密文缓冲区与加密调用的交叉引用集中；密钥常量附近常见加密调用链。
- 检测（动态）：进程启动后读取自身数据段/资源并调用 AES 或 BCrypt 解密，随后发起 C2 连接；解密后的配置字符串可作为内存扫描特征。
- 防御（分析侧）：先用 capa 缩小范围，再用交叉引用确认密钥来源，最后用明文结构（JSON 字段、URL/IP 可打印性）反向验证解密正确性。
- 防御（防守侧）：提取 C2 域名/IP、互斥量与模块开关做封禁与检测规则；EDR 关注“解密后立即外联”的行为序列，而不只是加密 API 调用。
