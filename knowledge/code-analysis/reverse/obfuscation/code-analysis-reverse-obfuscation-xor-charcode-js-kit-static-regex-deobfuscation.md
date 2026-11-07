---
id: code-analysis-reverse-obfuscation-xor-charcode-js-kit-static-regex-deobfuscation
title: Base64 多层打包 + XOR 字符码/整数混淆的 JS 工具包静态去混淆（正则常量折叠 + AI 语义重构）
type: scenario
domain: code-analysis
path: code-analysis/reverse/obfuscation
technique: xor-charcode-js-static-regex-deobfuscation
aliases:
- String.fromCharCode 异或去混淆
- JS 字符码数组还原
- 整数异或常量折叠
- Base64 多层 JS 拆分
- Coruna 工具包去混淆
- AI 辅助 JS 工具包分析
tags:
- obfuscation
- javascript
- deobfuscation
- static-analysis
- constant-folding
- regex
- ai-assisted
- exploit-kit
- malware-analysis
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V157
  verified_at: '2026-11-06T07:38:48+08:00'
  notes: 已对照原文与35张图核对：三种混淆模式（两处 fromCharCode XOR、整数 XOR）及示例值 '?e='、'GET'、-4096 与图14一致；Base64 分层拆出 group.html/framework.js/utils.js/config.js、Go 三条正则、AI 分步提示词、外联 icanhazip/8df9.cc、sha256(hashKey+moduleId)[0:40] 模块 URL（复算 6beef... 与图24/28一致）均属实。原文 iOS 13.0–17.2.1 为目标范围非组件版本；未执行样本。
---

## 一句话结论

当 JS 工具包只使用 `[..].map(x => String.fromCharCode(x ^ key)).join("")` 形式的字符码异或数组和 `(a ^ b)` 形式的整数异或常量时，无需执行样本：用三条正则做常量折叠即可批量还原全部字符串与整数；再把 Base64 多层打包的 `group.html/framework.js/utils.js/config.js` 拆开、格式化，最后交给 AI 做命名与流程重构，但必须用原始代码逐项核对，因为 AI 可能重构或漏掉关键逻辑。

## 原理

- **字符码异或**：`[69, 31, 71].map(p => String.fromCharCode(p ^ 122)).join("")` 是纯常量表达式——数组里每个数先与固定 key 异或，再转成字符拼接。它是确定性的，与运行环境无关，可直接在控制台或脚本里求值。
- **整数异或**：`(1232621146 ^ -1232617894)` 同样是常量表达式，求值得到 `-4096`，常用于数组长度、偏移、版本号或比较阈值。
- **多层 Base64 打包**：`group.html` 中嵌入的 Base64 字符串解码后得到 `framework.js`，后者又包含 Base64 的 `utils.js`（SHA1 哈希命名）与 `config.js`；逐层解码即可还原出相互调用的四个文件。打包只是隐藏文件边界，不改变可分析性。
- **正则常量折叠**：三类模式分别对应无花括号箭头函数、带 `return` 的箭头函数、以及整数异或。正则捕获数组、异或 key 和表达式，脚本求值后用结果替换原表达式，整份代码就从“混淆数据”降为“仅函数名/变量名混淆”。
- **为什么先脚本后 AI**：字符串/整数还原是确定性计算，交给脚本可避免模型猜测；AI 只负责语义层（重命名、控制流简化、外联地址提取），任务被降维。把原始混淆代码整体交给 AI 则容易漏读或编造。
- **为什么 AI 结果不能直接信**：模型做“可读化”时可能重构控制流、合并分支或删掉它认为无用的代码；关键的外联地址、模块 ID、条件分支可能被遗漏或改写。文章作者明确建议以原始代码为准交叉核对。
- **工具包加载链**：还原后可看到模块加载器用 `sha256(hashKey + moduleId).substring(0, 40) + ".js"` 生成模块 URL，再按 iOS 版本 flag 依次加载 WebKit 利用、PAC 绕过、沙箱逃逸与最终载荷模块；这解释了为什么模块文件名是 40 位十六进制哈希、且同一站点可用固定 hashKey 复现全部 URL。

## 触发条件

- 目标 JS 使用上述字符码异或数组/整数异或常量作为主要混淆，且 Base64 多层打包。
- 可获取原始混淆文件（水坑页面源码、浏览器缓存、抓包响应）。
- 分析环境能运行正则替换脚本（Go/Python/Node 均可）与格式化工具；可选 AI 对话或 AI IDE。
- 有原始代码或外部报告用于核对还原结果。

## 利用步骤

1. 保存水坑页面与隐藏 iframe 指向的 `group.html`；在浏览器 Network 面板确认后续加载的 JS 与指纹外联请求。
2. 提取页面中的 Base64 字符串，逐层解码，得到 `group.html`、`framework.js`、`utils.js`、`config.js`（后两者常以 SHA1 命名）。
3. 在控制台验证混淆模式：
   ```js
   [69, 31, 71].map(p => String.fromCharCode(p ^ 122)).join("")      // '?e='
   [126, 124, 109].map(x => {return String.fromCharCode(x ^ 57);}).join("") // 'GET'
   (1232621146 ^ -1232617894)                                        // -4096
   ```
4. 写脚本用三条正则批量替换（见 PoC）；对每个匹配求值后回填，输出 `*_dec.js`。
5. 用 VS Code/Prettier 格式化，检查是否还有第二层 Base64 或新的解码函数；若有则重复步骤 2–4。
6. 把四个已还原字符串的文件交给 AI，使用分步提示词：整体去混淆并重命名、输出完整运行流程与每步恶意意图、提取所有外联地址并做风险评估；要求每步等待确认，避免一次性输出被截断。
7. 用原始代码逐项核对 AI 结果：关键函数是否存在、外联 URL/域名/IP 是否完整、模块 ID 与版本分支是否一致；必要时对 JS 执行 `node --check` 做语法校验。
8. 还原模块加载算法：`baseUrl + sha256(hashKey + moduleId)[0:40] + ".js"`，按 iOS 版本 flag 映射到 WebKit/PAC/沙箱/载荷模块，形成完整攻击链视图。

## PoC

三条正则（Go 语言，来自实战脚本）：

```go
// 1) 无花括号箭头函数：[..].map(p => String.fromCharCode(p ^ key)).join("")
re1 := regexp.MustCompile(`(\[\s*([\d\s,-]+)\]\s*\.\s*map\s*\(\s*([a-zA-Z_$][\w$]*)\s*=>\s*String\.fromCharCode\s*\(\s*([a-zA-Z_$][\w$]*)\s*\^\s*(-?\d+)\s*\)\s*\)\s*\.\s*join\s*\(\s*(?:""|\s*|'')\s*\))`)

// 2) 带 return 的箭头函数：[..].map(x => {return String.fromCharCode(x ^ key);}).join("")
re2 := regexp.MustCompile(`(?s)(?P<full>\[\s*(?P<array>[\d\s,-]+)\]\s*\.\s*map\s*\(\s*[a-zA-Z_$][\w$]*\s*=>\s*\{?\s*return\s+String\.fromCharCode\s*\(\s*[a-zA-Z_$][\w$]*\s*\^\s*(?P<xor_key>[+-]?\d+)\s*\)\s*;?\s*\}?\s*\)\s*\.\s*join\s*\(\s*(?:""|''|)\s*\))`)

// 3) 整数异或：(a ^ b)
re3 := regexp.MustCompile(`\(\s*-?\d+\s*\^\s*-?\d+\s*\)`)
```

替换逻辑（示意）：

```python
import re

def fold_char_array(m):
    nums = [int(x) for x in re.split(r'[,\s]+', m.group(1).strip()) if x]
    key = int(m.group(2))
    return repr(''.join(chr(n ^ key) for n in nums))

def fold_int_xor(m):
    a, b = m.group(1), m.group(2)
    return str(int(a) ^ int(b))

code = open('group.html', encoding='utf-8').read()
code = re.sub(r'\[\s*([\d\s,-]+)\]\s*\.map\([^=]+=>\s*String\.fromCharCode\([^)]*\^\s*(-?\d+)\)\s*\)\.join\(""\)', fold_char_array, code)
code = re.sub(r'\(\s*(-?\d+)\s*\^\s*(-?\d+)\s*\)', fold_int_xor, code)
open('group_dec.html', 'w', encoding='utf-8').write(code)
```

模块 URL 还原：

```text
moduleUrl = baseUrl + sha256("cecd08aa6ff548c2" + moduleId).substring(0, 40) + ".js"
# moduleId e3b6ba10484875fabaed84076774a54b87752b8a
# => 6beef463953ff422511395b79735ec990bed65f4.js
```

说明：不同样本的 key、数组内容、回调写法会变化，需按实际代码调整正则；遇到 `atob`、`eval`、动态拼接或多层 Base64 时先静态拆分，不要直接执行。

## 变体与关联

- 变体：异或 key 可能写成分段表达式、十六进制或由另一个常量推导；数组可能包含负数、浮点或嵌套数组；正则需相应扩展。
- 变体：混淆层可能叠加 `atob`、`decodeURIComponent`、字符串反转、数组旋转；先做可静态求值的常量折叠，再处理必须运行的部分。
- 变体：AI 侧可用 AI IDE 直接索引四个文件并生成还原脚本；也可用网页 AI 只做流程与外联地址总结，但都要回原文件核对。
- 关联：[[code-analysis-reverse-obfuscation-ai-ide-assisted-js-deobfuscation]]（RC4 字符串数组 + AI IDE 的同类工作流，本卡补充静态 XOR 常量折叠分支）、[[code-analysis-reverse-obfuscation-js-aes-parameter-restore]]、[[code-analysis-reverse-frontend-request-response-encryption-automation]]、[[code-analysis-reverse-obfuscation-powershell-integer-array-scriptblock]]。
- 边界：样本使用运行时才生成的 key、服务端下发解码表、WASM 内部字符串或强控制流平坦化时，纯正则无法还原，需要动态调试或模拟执行；AI 结果未经核对不能作为结论。

## 检测与防御

- 检测（防御方）：页面源码中出现隐藏 iframe（宽高为 0、负定位）、`String.fromCharCode` 与 `^` 组合、超长 Base64 字符串、`sha256(...).substring(...)+".js"` 形式的模块 URL；浏览器对同一页面产生异常的公网 IP 查询与指纹上报请求；JARM/证书指纹与已知水坑站点相同。
- 检测（分析质量）：还原结果必须覆盖所有外联地址与模块 ID，并与原始代码/外部报告比对；AI 输出中的 URL、路径、模块 ID 需逐字核对，防止模型编造或漏项。
- 防御：混淆不是安全边界，攻击者可随时换编码；浏览器/网关应拦截隐藏 iframe 与可疑脚本加载，限制未知域外联；对 iOS 设备及时更新到不受该工具包影响的版本；威胁狩猎时结合流量、JARM 与域名情报关联同源水坑。
