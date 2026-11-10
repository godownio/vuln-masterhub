---
id: ctf-misc-blackbasta-decryptor-decryptblocks-patch
title: BlackBasta 勒索文件解密：No More Ransom 解密器 + decryptblocks.py 修补 flags 字段与 SRL_IGNORE_MAGIC
type: scenario
domain: ctf
path: ctf/misc
technique: blackbasta-decryptor-decryptblocks-patch
tags:
- ctf
- misc
- ransomware
- blackbasta
- decryption
- nomoreransom
- file-recovery
- incident-response
cve: []
severity: info
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V312
  verified_at: '2026-11-08T12:51:22+08:00'
  notes: 已对照原文 content.md 与18张图核对：图01 公众号给出 nomoreransom.org/zh/decryption-tools.html、搜索 BlackBasta 并下载，以及 sed -i 's/flags/"flags"/' ./decryptblocks.py、export SRL_IGNORE_MAGIC=1、./decryptblocks.py ./banana.jpg.sah28vut5 ./key.block 三条命令；原文另述前后 md5sum 不同、cp 为图片即可，卡片命令与流程一致。核对说明：decryptblocks.py 源码原文未给出，『flags 缺引号』与 SRL_IGNORE_MAGIC 跳过 magic 校验均为按 sed/环境变量名与工具行为的合理解释，卡片已用『可能/默认』措辞；原文未给解密器版本与下载文件名，卡片亦注明。dedup 除自身外候选为 LockBit3 现场特征、CryptNet 加密格式、PyInstaller 勒索恢复等，均为样本逆向/现场识别，无同一条『No More Ransom 官方解密器+decryptblocks 修补』工具链；dup-scan 无涉及本卡 pair。原子性：单一 CTF Misc 勒索文件恢复流程，不拆分。未验证点：未实际下载解密器/解密样本，原文未展示恢复后的图片；无版本信息；frontmatter 无 sources/source_url。
url: /docs/ctf/misc/ctf-misc-blackbasta-decryptor-decryptblocks-patch/
draft: false
kb_aliases:
- 初探勒索病毒
- BlackBasta decryptor
- decryptblocks.py
- SRL_IGNORE_MAGIC
- banana.jpg.sah28vut5
- key.block
- No More Ransom
---

## 一句话结论

拿到 BlackBasta 加密文件（如 `banana.jpg.sah28vut5`）和配套的 `key.block` 时，从 No More Ransom 下载 BlackBasta 解密器，先用 `sed -i 's/flags/"flags"/' decryptblocks.py` 修掉脚本里未加引号的 `flags` 字段，再 `export SRL_IGNORE_MAGIC=1` 跳过文件 magic 校验，执行 `./decryptblocks.py <加密文件> <key.block>` 即可恢复明文；解密前后 `md5sum` 不同，把输出改回图片扩展名即可查看。

## 原理

- **勒索解密的前提是拿到密钥材料**：BlackBasta 加密文件需要对应家族的解密器与每文件密钥块；CTF 题把 `key.block` 和加密样本一起给出，等价于受害者通过执法机构/厂商渠道获得了可用密钥。
- **官方解密器入口**：No More Ransom（nomoreransom.org）聚合了各家族的解密工具；在站内搜索 `BlackBasta` 下载后得到 Python 解密脚本及其依赖。
- **`flags` 引号修补**：`decryptblocks.py` 的代码里把 `flags` 当作字符串键/参数使用但未加引号，直接运行会把它当未定义变量（或与脚本内其它 `flags` 名字冲突）。`sed -i 's/flags/"flags"/'` 把它替换成字符串 `"flags"`，使脚本能正常解析。
- **`SRL_IGNORE_MAGIC=1`**：解密器默认会检查输入文件的 magic/文件头是否符合它预期的勒索格式，不匹配就拒绝处理。CTF 样本可能被改名、截断或只保留密文块，设该环境变量让脚本跳过 magic 校验，直接按密文块解密。
- **key.block 的配对**：`key.block` 是样本对应的密钥块文件，必须与密文来自同一加密会话；解密器用其中的密钥材料对密文块做逆运算，输出原始文件。
- **完整性判断**：加密前后 `md5sum` 必然不同；解密后应得到原始文件（原文是图片），把无意义后缀改回 `.jpg` 或直接 `cp` 成图片即可打开验证。

## 触发条件

- CTF Misc 给出了 BlackBasta 加密样本、`key.block` 和（通常）解密器/下载指引。
- 运行环境有 Python 与解密器依赖；原文在 Linux 下执行，Windows 可用 WSL/虚拟机。
- 样本与 key 配对；若 magic 不匹配，需要 `SRL_IGNORE_MAGIC=1`。
- 仅用于题目/授权取证环境，不能对真实受害文件盲目尝试。

## 利用步骤

1. 确认家族：看加密文件后缀/勒索说明，或在 No More Ransom、ID Ransomware 上匹配样本特征。
2. 在 nomoreransom.org 搜索 `BlackBasta`，下载对应解密器；解压得到 `decryptblocks.py` 等文件。
3. 修补脚本：`sed -i 's/flags/"flags"/' ./decryptblocks.py`，避免运行时 `flags` 未定义。
4. 跳过 magic 校验：`export SRL_IGNORE_MAGIC=1`。
5. 记录原密文哈希：`md5sum banana.jpg.sah28vut5`；执行 `./decryptblocks.py ./banana.jpg.sah28vut5 ./key.block`。
6. 再算一次 `md5sum` 确认变化；把输出文件 `cp` 成 `.jpg`/原扩展名，打开验证图片是否恢复。
7. 若失败：检查 Python 版本与脚本依赖、key.block 是否配对、密文是否被截断、是否需要用解密器的 GUI 版本或换用同家族其它工具。

## PoC

原文给出的命令序列：

```bash
# 1) 修脚本里的 flags 字段（补引号）
sed -i 's/flags/"flags"/' ./decryptblocks.py

# 2) 跳过解密器的 magic 校验
export SRL_IGNORE_MAGIC=1

# 3) 用配套 key.block 解密样本
./decryptblocks.py ./banana.jpg.sah28vut5 ./key.block

# 4) 前后对比哈希，确认输出变化
md5sum ./banana.jpg.sah28vut5
# 将解密输出改回图片后缀后查看
```

原文未给出解密器的具体下载链接与脚本版本，只说明在 nomoreransom.org 搜索 BlackBasta 下载；实际文件名/参数以下载到的工具为准。

## 变体与关联

- **其它家族**：LockBit、Conti、Babuk 等都有各自的官方/厂商解密器；流程相同（识别家族 → 下载工具 → 提供密钥/key 文件 → 解密），但参数与 magic 检查不同。
- **没有 key.block**：若密钥材料缺失，官方解密器无法工作；只能转向样本逆向/密钥恢复，相关思路见 [[defense-forensics-pyinstaller-ransomware-embedded-rsa-aes-ecb-recovery]] 与 [[ctf-reverse-ransomware-xor-crc32-mt19937-keystream]]。
- **Windows 专用解密器**：在 Linux 下可用 Wine 或 Windows 虚拟机；注意隔离样本，不要在宿主机直接双击。
- **边界**：解密器只对匹配版本/家族的密文有效；样本被二次修改（截断、拼接、改名）可能导致 magic/块对齐失败，需要 `SRL_IGNORE_MAGIC=1` 或手工修复文件头。

## 检测与防御

- **真实事件处置**：先隔离受害主机、保留加密样本与密钥块/勒索信，使用 No More Ransom、ID Ransomware 确认家族；不要自行支付赎金。
- **备份优先**：离线备份是唯一可靠恢复手段；定期演练恢复流程，避免备份也被加密。
- **样本安全**：解密工具从官方渠道获取并校验哈希；在隔离虚拟机中处理样本，避免二次感染。
- **检测**：监控 BlackBasta 常见的加密文件后缀、勒索信与批量改名行为；相关现场识别见 [[defense-detection-lockbit3-encrypted-file-artifacts]]（同类思路，家族特征需替换）。
- **合规**：仅对授权/自有样本操作；CTF 之外的文件恢复需取得数据所有者同意。
