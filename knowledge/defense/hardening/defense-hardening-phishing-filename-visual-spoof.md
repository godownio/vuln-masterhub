---
id: defense-hardening-phishing-filename-visual-spoof
title: 钓鱼附件视觉欺骗防御：扩展名显示、bidi/零宽净化、LNK 深度解析与渲染隔离
type: scenario
domain: defense
path: defense/hardening
technique: phishing-filename-visual-spoof-hardening
aliases:
- 双后缀防御
- RLO 文件名防御
- LNK 附件检测
- 文件名控制字符净化
- 图标/预览处理器隔离
- 钓鱼附件加固
tags:
- defense
- phishing
- filename-spoofing
- unicode
- bidi
- lnk
- hardening
- mail-gateway
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V216
  verified_at: '2026-11-07T04:43:39+08:00'
  notes: 已对照原文与全部9张图核对：强制显示扩展名、NFKC/零宽/bidi净化、LNK字段深度解析、图标/预览处理器隔离、AppLocker/WDAC等防御项均可在原文第三节找到依据。已修正指向不存在的LNK卡链接（改为现有 hidden-files-lnk-dll-sideload-delivery 卡）。未验证点：防御方案未在真实邮件网关/终端部署验证；非组件漏洞无版本；frontmatter无sources/source_url。dup-scan pair 35 为攻击/防御映射，均保留。
---

## 一句话结论

针对双后缀、RLO/零宽字符、LNK 显示名/图标伪装等“视觉欺骗”钓鱼，防御必须同时覆盖展示面（强制显示真实扩展名、转义 bidi/零宽字符）和解析面（邮件网关深度解包、解析 LNK 字段、隔离图标/预览处理器），不能只依赖扩展名黑名单。

## 原理

- Windows 按“最后一个扩展名 → ProgID → shell\open\command”决定文件类型和打开方式；Explorer 默认隐藏已知扩展名，用户看到的显示名可能与真实可执行类型不一致。
- Shell 层 `SHGetFileInfo`/`IExtractIcon` 会读取注册表映射、Shell 扩展和图标缓存；LNK 的 `NameString`/`Description`/`IconLocation` 可以在显示层伪装成 PDF/Word，而 `TargetPath`/`Arguments` 才是真正执行内容。攻击者利用的正是“显示面”和“执行面”的分离。
- 因此只在邮件网关用扩展名黑名单拦截 `.exe` 不够：双后缀、RLO、零宽字符、LNK、ISO/ZIP 容器、ADS 都能绕过；需要把附件当作不可信结构化数据，解析容器和 LNK 内部字段，并对文件名做规范化/净化。
- 展示面同样重要：即使网关放行，终端若强制显示真实扩展名、转义 bidi/零宽字符、双击前展示 LNK 目标/参数，用户仍有机会识破。

## 触发条件（适用场景）

- 企业邮件网关/下载代理接收外部附件，附件类型包括 ZIP/ISO/MHT/LNK/Office 等。
- 终端为 Windows，Explorer/邮件客户端会渲染文件名与图标，用户依据显示名判断文件类型。
- 现有防护仅做扩展名黑名单/静态哈希，未深度解包或解析 LNK 字段。
- 组织尚未强制“显示已知文件扩展名”、未禁止 LNK 附件、未隔离 Shell 扩展。

## 加固步骤

1. **展示面加固**：通过组策略强制“显示已知文件类型的扩展名”；在文件管理器/下载器中额外显示真实扩展名、将要执行的程序路径；对 bidi/零宽字符做转义或隔离显示，而不是原样渲染。
2. **文件名净化**：对附件/上传文件名做 NFKC/NFC 规范化，剥离 `U+200B/200C/200D/202A-202E/2066-2069/FEFF/00AD` 等控制/零宽字符；对强 RTL 可见字符（阿拉伯/希伯来字母）做隔离渲染（如 U+2068/2069）或转义提示，而不是简单删除。
3. **深度解包与内容嗅探**：网关打开 ZIP/ISO/MHT 等容器，解析 ADS 和 LNK 内部结构，提取 `LinkFlags`、`TargetPath`、`Arguments`、`IconLocation`、`LinkTargetIDList`；不要只看外层扩展名。
4. **LNK 高风险规则**：目标指向 UNC/临时目录/Downloads 的相对路径、使用 `mshta`/`powershell`/`rundll32`/`wscript`/`cscript`/`cmd` 等宿主、`IconLocation` 指向远程路径、文件名含不可见控制字符——命中即隔离/沙箱。
5. **附件策略**：禁止或转换 `.lnk` 附件；对来自 Internet 区域的可执行扩展要求二次确认；启用 SmartScreen/Safe Attachments/动态沙箱。
6. **渲染隔离**：把缩略图/图标/预览处理器放入隔离进程或沙箱，Shell 扩展强制代码签名与白名单；对来自不受信任网络位置的图标/缩略图默认不加载（Windows 11 已更保守）。
7. **终端执行控制**：AppLocker/WDAC/SmartScreen 阻止未签名/不受信任的可执行文件；对快捷方式双击前展示完整目标与参数。

## PoC

文件名校验伪代码：

```python
import unicodedata

DISALLOWED = {0x200B, 0x200C, 0x200D, 0x202A, 0x202B, 0x202C, 0x202D, 0x202E,
              0x2066, 0x2067, 0x2068, 0x2069, 0xFEFF, 0x00AD}

def sanitize_filename(name: str) -> str:
    name = unicodedata.normalize("NFKC", name)
    return "".join(ch for ch in name if ord(ch) not in DISALLOWED)
```

LNK 字段检查清单（示意）：

```text
LinkFlags
TargetPath / LinkInfo / LinkTargetIDList
Arguments
IconLocation
NameString / Description
是否指向 UNC、Temp、Downloads、网络位置
宿主是否为 mshta/powershell/rundll32/wscript/cscript/cmd
```

## 变体与关联

- 关联：[[pentest-initial-access-rtl-override-filename-spoof]]（U+202E 基础手法，本卡是其防御映射）。
- 关联：[[pentest-initial-access-filename-spoof-av-evasion-zero-width-arabic-rtl]]（零宽字符/强 RTL 可见字符绕过杀软，本卡覆盖其净化与渲染防御）。
- 关联：[[pentest-initial-access-hidden-files-lnk-dll-sideload-delivery]]（LNK 显示名/图标伪装，本卡覆盖 LNK 深度解析与渲染隔离）。
- 关联：[[pentest-initial-access-lnk-mshta-remote-hta]]、[[pentest-initial-access-lnk-winget-config-phishing]]（具体 LNK 投递链，本卡提供通用检测项）。
- 边界：网关无法解包加密压缩包/未知容器、终端用户忽略警告、组织未部署组策略时，防御效果受限；强 RTL 可见字符本身是合法字母，不能简单全部拦截，需用隔离/转义方式处理。

## 检测与防御

- 检测：附件文件名含 bidi 控制/零宽字符、双后缀（`*.pdf.exe` 等）、显示名与类型列不一致；LNK 指向脚本宿主/远程图标/临时目录；邮件网关出现深度解包失败或加密容器。
- 防御：组策略显示扩展名；网关文件名净化 + 深度解包 + LNK 字段解析；禁止 LNK 附件；SmartScreen/AppLocker/WDAC；Shell 扩展隔离与签名。
- 加固：定期红队测试（双后缀/RLO/零宽/LNK/ISO 容器），根据绕过样本更新网关规则；对用户开展“不要仅凭文件名判断类型”的培训。
