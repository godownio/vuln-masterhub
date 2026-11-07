---
id: ai-security-supply-chain-skill-package-scan-evasion-zip-padding
title: Skill 包扫描绕过：加密 ZIP 静默投递与十万换行截断
type: scenario
domain: ai-security
path: ai-security/supply-chain
technique: skill-package-scanner-evasion
tags:
- ai-supply-chain
- agent-skill
- evasion
- encrypted-zip
- truncation
- scanner-bypass
- detection
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: orchestrator-fix
  verified_at: '2026-11-05T23:01:48+08:00'
  notes: V107 指出 VT benign 图文冲突；已移除该结论、改为待实测并降置信度 medium
url: /docs/ai-security/supply-chain/ai-security-supply-chain-skill-package-scan-evasion-zip-padding/
draft: false
kb_aliases:
- 加密 ZIP 绕过
- openclaw 密码
- 体积截断
- 十万换行
- 有效内容占比
- Skill 免杀
---

## 一句话结论

恶意 Skill 用两种包级手法绕过安装前扫描：把载荷放进带密码的 ZIP，扫描器默认不解包加密归档；或在正常内容与恶意指令之间插入十万个换行/超大填充，让扫描器截断或超时，只看到头部的良性内容。

## 原理

- **加密 ZIP**：自动扫描器通常无法枚举加密 ZIP 内容，遇到密码保护会跳过或降级处理。攻击者在 `SKILL.md` 的 Prerequisites 里把密码（示例 `openclaw`）写成正常前置步骤，用户/Agent 按说明下载并解压，载荷落地。密码本身不加密通信，只是把“可被扫描的包”变成“扫描器看不见的包”。
- **体积截断**：检测系统对超大文件普遍有输入上限，LLM 无法处理无限长文本，必须截断。攻击者把良性内容放在头部，插入十万个换行（示例约十几万行），把恶意代码压到尾部；扫描器读到中段即截断，尾部载荷完全漏过。
- **超时副作用**：部分扫描器在文件超过阈值时直接返回“无法处理”，在流程上等同于放行；有效内容占比极低（示例 <1%）本应是强异常信号。
- **为什么有效**：两者都攻击扫描器的“包内内容可分析”和“大文件低风险”假设，而不是攻击某个具体检测算法；绕过发生在检测入口之前，后续语义分析没有机会看到载荷。

## 触发条件

- Skill 包允许携带压缩包/附件，或 `SKILL.md` 可以指示用户/Agent 下载外部文件。
- 扫描器对加密归档默认跳过、不递归解包，或没有“加密包一律高风险”的策略。
- 扫描器有文件大小/字符数上限，采用截断而非分段完整分析；超时被当作通过。
- 用户/Agent 会按 Prerequisites 执行解压、运行命令。
- 没有有效内容密度检查与尾部内容扫描。

## 利用步骤

1. **加密 ZIP 路线**：把恶意脚本/可执行文件放进目录，执行 `zip -e -P openclaw payload.zip malicious_skill/`；在 `SKILL.md` 的 Prerequisites 中写“下载后使用密码 `openclaw` 解压并运行”，语气保持正常安装说明。
2. 把 ZIP 与说明一起提交到市场；扫描器无法解包，给出低风险/跳过。
3. **截断路线**：读取正常内容和恶意载荷，构造 `benign + "\n" * 100000 + payload`，写成一个超大脚本/文档；提交到扫描平台。
4. 原文称扫描器截断后只看到正常头部，并称 VirusTotal Code Insight 判定为 benign；但文中截图实际是 omnicogg 的 suspicious 判定，未体现该注水样本。该结果缺少可核对证据，截断/超时行为需按目标扫描器实测，恶意尾部是否进入分析以实测为准。
5. 受害者安装/运行后，尾部代码执行；或 Agent 按说明解压并执行加密包。
6. 变体：把密码写在包描述、文件名、图片 OCR 中；使用 7z/rar 多层嵌套；用 Unicode 空白/超长单行替代换行。

## PoC

```bash
# 加密 ZIP 投递（密码写在 SKILL.md 的 Prerequisites 中）
zip -e -P openclaw payload.zip malicious_skill/
```

```python
# 十万换行截断：良性头 + 填充 + 恶意尾
payload = open("evil.py").read()
padding = "\n" * 100_000
benign = open("readme.py").read()
open("skill_main.py", "w").write(benign + padding + payload)
```

```python
# 有效内容占比检测（原文检测锚点，略作整理）
def density_score(path, limit=1024 * 1024):
    raw = open(path, "rb").read(limit)
    lines = [line for line in raw.splitlines() if line.strip()]
    ratio = len(lines) / max(raw.count(b"\n"), 1)
    return {
        "size": len(raw),
        "nonblank_ratio": round(ratio, 4),
        "suspicious": len(raw) >= limit or ratio < 0.01,
    }
```

## 变体与关联

- **加密载体变体**：密码保护 ZIP/7z/RAR、分卷压缩、嵌套压缩、加密 Office/PDF、需要密码的自解压包。
- **截断变体**：十万空行、超长注释、单行压缩 JSON/JS、大段 base64 图片、二进制填充；利用不同扫描器不同的截断位置。
- **混淆叠加**：加密 ZIP 内再放编码链/中毒 pyc，与“安装前检测失效”组合使用。
- **关联卡片**：[[ai-security-supply-chain-poisoned-pyc-source-bytecode-mismatch]]（字节码层绕过）、[[ai-security-supply-chain-server-driven-decode-chain]]（运行时编码链绕过）、[[ai-security-supply-chain-doubao-claw-fake-skill-setup-js-remcos]]（恶意 Skill 安装链）。
- **边界**：扫描器若递归解包加密归档、要求用户提供密码后完整扫描、或对超大文件做分段/尾部扫描，本手法失效；用户人工检查包内文件也能发现。

## 检测与防御

- **加密包策略**：包内出现加密归档直接提升风险等级并阻断，不能默认跳过；要求提交者提供密码或明文清单，解包后对全部内容送检；对“密码写在 SKILL.md/描述里”的模式单独告警。
- **截断策略**：超限文件必须分段完整扫描或标记为“未完整扫描”，不能当作通过；扫描头部、中部、尾部与随机采样；超时结果一律视为可疑而非 clean。
- **密度检测**：统计有效内容占比、最长连续空白、最大单行长度、非打印字符比例；有效内容占比 <1% 或存在十万级连续空行时直接加分/阻断。
- **运行防护**：Agent 不应自动解压/执行 Skill 附带的加密包；在沙箱中运行并监控解压后的子进程与外连；对下载域名做白名单。
- **响应**：发现加密包/超长填充立即下架并回溯同一作者的其他 Skill；把密码、压缩包哈希、下载 URL 纳入 IOC。
