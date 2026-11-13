---
id: code-analysis-reverse-obfuscation-jse-dropper-jscriptencode-unicode-dynamic-charcode-regex
title: JScript.Encode + Unicode 转义 + 动态 String.fromCharCode 的 JSE Dropper 静态去混淆与 IOC 提取
type: scenario
domain: code-analysis
path: code-analysis/reverse/obfuscation
technique: jse-dropper-jscriptencode-unicode-dynamic-charcode-regex-deobfuscation
aliases:
- JSE dropper 去混淆
- JScript.Encode 解码
- Unicode 转义正则还原
- String.fromCharCode 动态参数混淆
- Zusy/Tinba dropper 分析
tags:
- obfuscation
- javascript
- deobfuscation
- static-analysis
- regex
- malware-analysis
- jscript-encode
- dropper
- ioc
- windows
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-12'
verification:
  verified_by: verifier-V557
  verified_at: '2026-11-12T00:26:10+08:00'
  notes: 已对照原文与5张截图核对（图02/03内容相同）：JScript.Encode 解码→Unicode 转义(\u0\d{3})+还原→自定义 String.fromCharCode(static+dynamic) 折叠（示例 96+3=99='c'）→环境检测(进程名/路径/所有者域/所有者名包含 VM 特征)→for 循环生成 C2 动态参数 hashere→主载荷 Zusy/Tinba；原文未见最终 C2 通信截图，样本未执行。修正：删除原文未提及的 WMI 表述，补入原文的 rar/jse SHA256，把主载荷哈希标注为原文未区分 base64 解码前后。dedup 仅命中卡片自身；fake-captcha-hta、word-macro-jscript-encode、xor-charcode 候选均为不同样本/不同混淆组合，非同链，保留。
---

## 一句话结论

当 `.jse` 恶意 dropper 采用「JScript.Encode → Unicode 转义标识符 → 自定义 `String.fromCharCode(静态参数+动态参数)` 字符串拆分 → 大量垃圾代码」的链式混淆时，不必依赖动态分析：先用微软 JScript.Encode 解码器还原成 `.js`，再用 Python 正则批量替换 Unicode 转义与动态字符码调用，即可把几十万字符的单行脚本还原为可读代码，进而提取落盘文件、C2 URL 与环境检测条件等 IOC。

## 原理

- **JScript.Encode 只是编码，不是加密**：`.jse` 由 Windows Script Host 按 `JScript.Encode` 格式执行，微软公开了编码算法，存在现成解码器；拿到样本后先离线解码得到混淆的 `.js`，这是第一层。
- **Unicode 转义混淆**：解码后的代码把标识符写成 `url...` 形式（如变量名整体转义）。这属于编码式混淆，用 `(\\u0\d{3})+` 正则匹配、回调中 `decode('unicode-escape').encode('utf-8')` 即可无副作用替换；它只增加可读难度，不改变语义。
- **自定义字符串拆分**：核心混淆把 `String.fromCharCode(x)` 拆成带垃圾属性的对象方法调用：函数返回表达式形如 `String[...] + [...] + rox(<static> + pi)`，调用处再以 `..., 'Code', <dynamic>` 形式传入动态参数；两者相加才是目标 ASCII 码（原文示例 96 + 3 = 99 = `'c'`）。静态参数写在返回表达式附近，动态参数在调用点，必须两处都解析才能还原字符。
- **正则常量折叠的可行性**：该模式是确定性的字符串构造，不依赖运行环境；用两条正则分别抓静态/动态参数，再在 Python 回调里求值替换，即可批量折叠。原文静态参数正则近似 `return\s*String.*?\((\d{1,3})\s*[+]\s*pi\)`，动态参数正则近似 `, 'Code', (\d{1,3})\)`。
- **为什么要按上下文修正正则**：同一混淆模式会出现在语句、`try/catch`、`while`、变量定义等不同位置，右边界分别是 `=`、`!`、`)`、`,`、`]`、`+`、空白或 `;`；只匹配单一右边界会漏掉部分调用。把结束字符类补全（`(=|!|\)|,|*|]|+|\s|;)`）后再跑一遍，才能覆盖全部调用点。
- **环境检测导致动态分析失效**：样本用进程枚举收集「进程名、可执行路径、所有者域、所有者名」，与 VM/沙箱/逆向机特征字符串做包含判断；命中即不执行后续逻辑。这就是样本在分析虚拟机中“跑不起来”的原因，也是必须回到静态去混淆的直接动机。
- **C2 分发协议**：最终 URL 含静态参数、随机参数和一个由 `for` 循环技巧生成的动态参数（原文称 `hashere`），PHP 端只有在该参数正确时才返回压缩/打包后的二进制；直接访问 C2 页面不会拿到木马。注释掉原 HTTP 调用、改为打印拼接好的 URL，即可复现请求并下载载荷。
- **最终载荷识别**：按上述 URL 下载得到 base64 编码的二进制，解码后按 SHA256 与家族特征比对，归类为银行木马 Zusy（Tinba）变体。

## 触发条件

- 拿到 `.jse`/JS dropper 样本（邮件附件、压缩包、水坑页面等），且无法或不宜动态执行。
- 样本主要采用编码式混淆（JScript.Encode、Unicode 转义）与确定性字符码拼接，而非依赖运行期密钥的加密。
- 分析机具备 Python/任意支持正则的脚本语言、代码美化工具与 JScript.Encode 解码器。
- 若动态分析被环境检测阻断，静态路线是唯一可行路径。

## 利用步骤

1. **去 JScript.Encode**：用公开的 JScript.Encode 解码器把 `.jse` 还原为 `.js`；记录样本与解压包的 SHA256 作为 IOC。
2. **格式化**：先对原始脚本做美化仅用于阅读；所有替换在未格式化的原始文件上执行，避免美化改变字符串边界。
3. **还原 Unicode 转义**：用 `(\\u0\d{3})+` 正则加回调解码，得到变量名可读的版本。
4. **识别核心混淆模式**：在美化代码中定位 `String` + `fromChar` + `Code` 拼接与 `(<static> + pi)`、`'Code', <dynamic>` 的调用形态，确认是 `String.fromCharCode(static+dynamic)` 的变形。
5. **编写并调试折叠脚本**：两条正则分别抓静态/动态数字，回调求值后替换；在 Notepad++ 等编辑器中先验证正则，再批量执行；根据上下文补全右边界字符类，反复运行直到无剩余匹配。
6. **阅读还原代码**：定位恶意行为——`%TEMP%` 下落盘 `.exe` 与 `.gop`、遍历磁盘把指定扩展名文件列表写入 `saymname.txt`、环境检测进程名单、C2 基址与参数生成逻辑。
7. **绕过环境检测做网络侧确认**：注释/跳过检测分支，把拼好的下载 URL 打印出来，手工请求 C2 获取二进制；解码 base64 并计算哈希、比对家族。
8. **整理 IOC**：落盘路径与文件名、C2 域名/URL 参数格式、样本哈希、环境检测特征串，用于检测与阻断。

## PoC

Unicode 转义还原（原文思路的等价实现）：

```python
import re

def unicode_replace(m):
    return m.group().decode('unicode-escape').encode('utf-8').decode('utf-8', 'ignore')

with open('decoded.js', 'r', encoding='utf-8', errors='ignore') as f:
    for line in f:
        print(re.sub(r'(\\u0\d{3})+', unicode_replace, line))
```

动态字符码折叠（按原文模式归纳，实施前需在样本上验证边界）：

```python
# 静态参数: return ...(<static> + pi);   动态参数: ..., 'Code', <dynamic>)
static_re = re.compile(r'return\s*String.*?\((\d{1,3})\s*[+]\s*pi\)')
dynamic_re = re.compile(r",\s*'Code'\s*,\s*(\d{1,3})\s*\)")
# 对每个混淆调用块：chr(int(static) + int(dynamic)) 后替换整个表达式
# 结束边界需覆盖 = ! ) , * ] + 空白 ; 等上下文
```

```text
# 样本侧 IOC（原文记录，未执行）
# - 压缩包 SHA256: 0d72340c876292dcdc8dfa5b3b1cc7b6010902a2d28b5b15c8c35a3a284e7d35
# - .jse 样本 SHA256: 652566914671a9d5fb5ad0b75b6c9023fa8c9cff2c2d2254daad78ba40c14e0b
# - %TEMP% 目录下的 .exe 与 .gop 文件
# - %TEMP%\saymname.txt（磁盘文件清单）
# - C2 下载 URL 含动态参数，参数错误时不返回载荷
# - 下载的主载荷 SHA256（原文未区分 base64 解码前后）: 1572b8cc6dc1af0403bf91e24b20f9c39f6722258329b0bafa89f300989393f5
```

## 变体与关联

- 变体：JScript.Encode 之后可能再叠加 Base64、`eval`、`Function` 构造、数组下标取关键字等层；逐层按“编码 → 美化 → 模式识别 → 正则/脚本折叠”顺序处理。
- 关联：[[code-analysis-reverse-obfuscation-xor-charcode-js-kit-static-regex-deobfuscation]]（同为字符码混淆的正则常量折叠，但那是 XOR 常量数组，本卡是静态+动态双参数求和，需要同时解析调用点）。
- 关联：[[code-analysis-reverse-obfuscation-fake-captcha-hta-js-charcode-powershell]]（JS/HTA 字符码混淆 + PowerShell 下一阶段，同属脚本 dropper 分层分析）。
- 关联：[[code-analysis-reverse-obfuscation-javascript-obfuscator-v530-string-array-extraction]] 等 javascript-obfuscator 系卡片（字符串数组方案，与手写自定义函数不同）。
- 边界：环境检测（进程名/所有者/沙箱特征）会让动态分析静默失败；静态还原出检测逻辑后，才有针对性地改条件或手工构造 C2 请求。

## 检测与防御

- 检测：邮件网关/终端阻断 `.jse`、`.js`、`.vbs` 等 WSH 脚本附件；监控 `wscript.exe`/`cscript.exe` 启动及其子进程。
- 检测：`%TEMP%` 下出现新的 `.exe`/`.gop` 组合与 `saymname.txt` 类枚举清单文件；进程/任务列表枚举行为异常频繁。
- 检测：按 IOC 匹配 C2 URL 形态（含动态参数校验的下载端点）、样本哈希与进程特征串。
- 防御：通过组策略/ASR 限制 Windows Script Host；禁用不必要的 WSH；对下载的可执行体做信誉与沙箱分析；AMSI 日志留存。
- 反分析对抗提示：分析时优先静态还原，动态执行前先确认无环境检测，避免样本自删除或反虚拟机行为。
