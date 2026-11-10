---
id: code-analysis-reverse-windows-bloodalchemy-config-1byte-key-decrypt
title: BloodAlchemy 配置解密：Store 下 15 字符随机名文件与 [长度][1 字节密钥][密文] 自变密钥算法还原 C2/mutex/持久化参数
type: scenario
domain: code-analysis
path: code-analysis/reverse/windows
technique: bloodalchemy-config-1byte-key-custom-decrypt
aliases:
- BloodAlchemy 配置提取
- dec_cmt 解密
- 1 字节密钥配置解密
- C:\ProgramData\Store 配置
- BloodAlchemy C2 提取
- Deed RAT 配置结构
tags:
- reverse
- windows
- malware
- bloodalchemy
- deed-rat
- config-extraction
- idapython
- c2
- mutex
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-09'
verification:
  verified_by: verifier-V352
  verified_at: '2026-11-09T00:58:45+08:00'
  notes: 已对照原文与20张图核对：配置来源（内嵌 + C:\ProgramData\Store 下15个a-zA-Z字符文件名）、offset_config=0x534（图10）、[1B size][1B key][密文] 结构与 e_c2_size=0x25/e_c2_key=0x4A/e_c2_data（图12）、dec_cmt 自变密钥算法四行与 return dec[:-1]（图11）、C2 示例注释 TCP://cdn1ac7bdd3.jptomorrow.com:443（图12，卡内已 defang）、mutex DFYNBEDKJHGAFSTIJECYUKFDEUJH、服务名 Test/Digital Imaging System、Run 键与 ONLOGON、注入目标进程、persistence flag 1-4（图12-14）均一致。小瑕疵：size 字节实为密文块长度（脚本按 size 读取并 return dec[:-1]，明文为 size-1），卡内'明文长度'表述宜按此理解；PoC 中 C2 示例只给 8 字节密文并已注明需读满 0x25 字节，直接运行会越界，属示例省略。未执行样本，示例 C2 仅作结构演示。与 loader/行为卡为不同技术面，与 SilentCryptoMiner 32字节循环 XOR 等候选不同链。无 sources/source_url；dup-scan(19:10)早于本批建卡无涉及 pair。
---

## 一句话结论

BloodAlchemy 的配置以加密状态嵌在载荷中（偏移 `0x534` 处定位），也可从 `C:\ProgramData\Store` 下文件名由 15 个大小写字母组成的文件加载；每个配置项是 `[1 字节长度][1 字节密钥][密文]` 结构，用"密钥随字节序号自变"的异或算法解密，可离线还原出 mutex、C2（最多 10 个）、持久化方式、注入目标进程等关键参数。

## 原理

- **配置来源**：配置在载荷处理过程中单独解密使用；若 `C:\ProgramData\Store` 下存在一个文件名为 15 个 `{a-zA-Z}` 字符的文件，则该文件被当作恶意软件配置加载，解密算法与载荷一致。这意味着攻击者可以不更新载荷、只替换配置文件来切换 C2 或行为。
- **配置布局**：IDAPython 脚本 `dec_cmt(offset)` 读取的每个条目格式为：第 1 字节 `size`（明文长度）、第 2 字节 `key/iv`、随后 `size` 字节密文。载荷结构体中 `offset_config`（示例值 `0x534`）指向配置区，各字段通过 `get_value_from_config_by_arg0(<偏移>)` 读取；字段包括 `createmutex_flag`/`mutex_value`、`selftdelete_flag`、`antibdg_flag`、`checksandbox_flag`、`install_reg`/`install_dir`/`exe`/`mal_dll`/`blob`、`persistence_flag`、服务名/注册表键值/计划任务名、进程注入与进程镂空开关及目标进程列表、C2 列表等。
- **解密算法（关键）**：对第 i 个密文字节，先用当前 1 字节密钥异或得到明文字节，再让密钥自变：
  - `dec[i] = (iv ^ enc[i]) & 0xFF`
  - `ku0 = (iv << (i % 5 + 1)) & 0xFF`
  - `ku1 = (iv >> (7 - i % 5)) & 0xFF`
  - `iv = (iv + (ku0 | ku1)) & 0xFF`
  循环 `size` 次后去掉末尾 1 字节（原文脚本 `return dec[:-1]`，末尾为 NUL/填充）。算法只依赖 1 字节密钥与序号，按脚本可完全离线复现。
- **C2 结构**：C2 条目也是同型加密块：`e_c2_size`（1 字节长度）、`e_c2_key`（1 字节密钥）、`e_c2_data`（密文）；示例样本加密数据以 `1E 9D 09 19 7A D0 9D 9D ...` 开头，解出形如 `TCP://<域名>:443` 的 C2（原文截图示例为 `cdn1ac7bdd3.jptomorrow[.]com:443`）。载荷最多可容纳 10 个 C2 目的地，观察到的样本只有一个。
- **同一算法复用**：配置以外的其他加密数据（如特定目录路径）也使用相同结构/算法，脚本可通用。
- **为什么能离线还原**：密钥就存在密文前 1 字节，算法无外部秘密；拿到载荷或配置块即可逐条解出全部字段，不依赖运行样本或连接 C2。

## 触发条件

- 拿到 BloodAlchemy 载荷（已按加载链解出 `45AB45AB` 自定义格式）或 `C:\ProgramData\Store` 下的 15 字符配置文件。
- 能定位配置区偏移（结构体 `offset_config`，示例 `0x534`）或 C2 结构体的文件偏移。
- 分析环境有 Python（或 IDAPython）即可，无需 Windows。

## 利用步骤

1. **定位配置**：在载荷结构体中找 `offset_config`（示例 `0x534`）；检查 `C:\ProgramData\Store` 下是否有 15 个字母命名的文件，若有则优先按文件加载路径分析。
2. **提取加密块**：按字段偏移读取 `[size][key][data]` 三元组；C2 列表从 `e_c2_size`/`e_c2_key`/`e_c2_data` 结构开始，按 size 逐条读取。
3. **实现 dec_cmt**：用下面的 Python 函数按序号自变密钥解密；注意返回前去掉末尾 1 字节。
4. **解出字段**：输出 mutex、安装目录/注册表、运行键、服务名、计划任务名、持久化 flag、注入/镂空目标进程、C2 与协议 ID；与载荷中的使用逻辑交叉验证（如持久化 flag 0-4 对应不同组合）。
5. **整理 IOC**：把 C2 域名/IP、端口、mutex、服务名、注册表路径、计划任务名、Store 文件名规则写成检测规则；如观察到多套 C2，记录协议类型（TCP_MUX/HTTP(S)/UDP/DNS/PIPE_SMB）。

## PoC

```python
def dec_blob(data: bytes) -> bytes:
    """data = [1B size][1B key][size B ciphertext]"""
    size = data[0]
    iv = data[1]
    enc = data[2:2 + size]
    out = bytearray()
    for i in range(size):
        out.append((iv ^ enc[i]) & 0xFF)
        ku0 = (iv << (i % 5 + 1)) & 0xFF
        ku1 = (iv >> (7 - i % 5)) & 0xFF
        iv = (iv + (ku0 | ku1)) & 0xFF
    return bytes(out[:-1])

# 示例：从载荷/配置文件中按偏移取出一个加密块
# blob = payload[off: off + 2 + payload[off]]
# print(dec_blob(blob))
```

C2 条目示例（原文截图数据，key=0x4A，size=0x25）：

```python
blob = bytes([0x25, 0x4A, 0x1E, 0x9D, 0x09, 0x19, 0x7A, 0xD0, 0x9D, 0x9D])
# 实际需读满 0x25 字节密文后再调用 dec_blob；解出形如 TCP://<c2>:443 的字符串
print(dec_blob(blob))
```

说明：示例仅演示结构与算法，完整密文需按实际样本读取。

## 变体与关联

- **变体（配置载体）**：内嵌载荷 vs `C:\ProgramData\Store` 下 15 字符文件；后者便于攻击者在不替换主载荷的情况下更换配置。
- **变体（家族）**：Deed RAT 使用同型配置结构与加密数据偏移（offset）机制，BloodAlchemy 继承自 ShadowPad/Deed RAT；字段偏移与常量可能随版本变化。
- **变体（算法）**：1 字节密钥的自变算法可能被改版替换；识别要点仍是 `[size][key][data]` 块与 `offset_config` 交叉引用。
- 关联：[[code-analysis-reverse-windows-bloodalchemy-loader-aes-fnv-lznt1]]（先解出载荷才能拿到配置）、[[defense-detection-bloodalchemy-deed-rat-behavior-ioc]]（配置字段对应的行为与狩猎特征）、[[code-analysis-reverse-windows-blacknet-config-aes-pbkdf2-extract]]（另一家族的配置解密）。
- 边界：配置文件缺失、字段偏移被改或使用非 ASCII 编码时需按样本调整；别把示例 C2 当作活跃基础设施。

## 检测与防御

- **检测**：扫描 `C:\ProgramData\Store` 下 15 个字母命名的文件；内存/文件搜索 `offset_config` 结构与 `45AB45AB` 载荷 magic；网络侧匹配解出的 C2 域名/IP；EDR 监控对 Store 目录的写入与读取。
- **防御**：限制普通进程对 `C:\ProgramData\Store` 的写入；对可疑配置文件做沙箱解密；通过应用白名单阻止未签名载荷加载。
- **响应**：解出全部 C2、mutex、持久化参数后，按 C2 封禁、按服务名/计划任务名/运行键清理持久化；评估配置中注入目标进程是否已被感染。
