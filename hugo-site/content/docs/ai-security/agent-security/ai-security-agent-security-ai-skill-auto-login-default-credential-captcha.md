---
id: ai-security-agent-security-ai-skill-auto-login-default-credential-captcha
title: AI Skill 自动登录流水线：agent-browser 快照定位 + 本地默认口令库 + ddddocr 验证码识别与失败自修复
type: scenario
domain: ai-security
path: ai-security/agent-security
technique: ai-skill-auto-login-default-credential
tags:
- ai-security
- agent-security
- skill
- agent-browser
- browser-automation
- default-credentials
- captcha
- ddddocr
- nacos
- self-repair
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V157
  verified_at: '2026-11-06T07:38:50+08:00'
  notes: 已对照原文与8张图核对：Nacos 2.1.0 用 nacos/nacos 登录成功进入配置管理（图01）；验证码站点 admin/admin 识别出 Ahq6 但 URL 仍停留 /login、提示 password_error（图07/08），原文“自动修复后成功识别验证码”仅指 OCR 成功、并非登录成功，卡内已如实说明；captcha_recognize.py 的 stdin 自修复改动与图07一致。无版本字段（Nacos 2.1.0 仅为演示目标）；PoC 为按截图最小化示意。
url: /docs/ai-security/agent-security/ai-security-agent-security-ai-skill-auto-login-default-credential-captcha/
draft: false
kb_aliases:
- Auto Login Skill
- agent-browser 自动登录
- AI 自动填表登录
- 默认口令自动验证
- ddddocr 验证码 stdin
- Skill 自修复
- 智能爆破工具
---

## 一句话结论

把“识别登录页 → 查本地默认口令库 → 用 agent-browser 的快照引用填表提交 → 按 URL/快照变化判断是否成功”封装成 `SKILL.md`，再用 `ddddocr` 脚本经 stdin 识别图形验证码，AI Agent 就能在授权测试中自动完成默认口令登录；原文在 Nacos 2.1.0 上以默认 `nacos/nacos` 登录成功，验证码站点则因演示口令错误未成功，展示的是可复用的自动化编排而非新的认证漏洞。

## 原理

- AI Agent（Claude Code/OpenCode/Cursor 等）通过 `skills` 管理器加载 Skill：`SKILL.md` 用自然语言描述触发场景与步骤，`references/` 放默认口令库，`scripts/` 放验证码识别脚本。Agent 读取这些文件后按流程调用外部 CLI 工具，把“人看页面、查资料、敲表单”变成可重复执行的闭环。
- `agent-browser` 提供确定性的浏览器操作原语：`open` 打开页面，`snapshot -i` 输出带 `@eN` 引用的可访问性树，`fill @eN "value"` 填表，`click` 提交，`eval` 在页面内执行 JS，`screenshot` 留证。Agent 不需要写选择器代码，只要读快照里的字段名和引用即可定位用户名/密码/验证码/提交按钮。
- 默认口令是成本最低的入口：Nacos、路由器、NAS、后台管理系统等常保留出厂/示例账号。本地口令库把“系统指纹 → 默认账号密码”的映射固化，Agent 先按 URL、页面标题、品牌文案识别系统类型，再取对应口令尝试，避免每次人工搜索。
- 图形验证码若只是简单字符图片，本地 OCR 可识别。`agent-browser eval` 能读取验证码 `<img>` 的 `src`，用 `fetch` + `FileReader` 转成 data URL；`ddddocr` 直接在本地做分类，不依赖打码平台。
- 长参数会导致命令失败：原文最初把 base64/data URL 作为命令行参数传给识别脚本，参数过长使脚本报错；Agent 读到错误后把脚本改为支持 `--stdin`，由管道传入图片数据，再重试成功。这就是所谓“自修复”——Agent 读取工具输出、修改自身脚本/参数并重跑，而不是一次性固定流程。
- 成功判定不靠单一信号：URL 从 `/login` 变为后台路径、快照中出现“配置管理/服务管理/权限控制”等菜单、页面错误文案消失，三者结合可降低误判；失败则记录并尝试下一条口令或结束，避免盲目高频请求。

## 触发条件

- 有明确授权的目标，且允许自动化登录测试与受控的失败次数。
- 目标登录页可访问，表单为常规用户名/密码（可带图形验证码），页面无强制 MFA 或设备绑定。
- 本地可安装/运行 `skills`、`agent-browser`（首次需下载 Chrome for Testing）与 `ddddocr`。
- 目标系统有已知默认口令或常见初始口令模式，且未强制首次登录改密。
- 验证码为简单字符图、无强行为风控；若验证码复杂或带滑块，需要换 OCR/打码方案。
- 账号锁定/速率限制阈值高于测试所需次数，或测试使用单账号单次默认口令尝试（不进行字典爆破）。

## 利用步骤

1. 安装并确认工具：`npm i skills`、`npm install -g agent-browser && agent-browser install`，用 `npx skills list` 查看已加载 Skill。
2. 创建 Skill 目录：`SKILL.md` 写清触发词（默认密码、自动登录、管理后台、验证码识别）与流程；`references/default_passwords.md` 维护“系统类型/默认账号/默认密码/备注”；`scripts/captcha_recognize.py` 用 ddddocr 识别图片。
3. 让 Agent 执行：给出目标 URL 和“使用 auto_login 登录”的指令；Agent 调 `agent-browser open <url> --headed`。
4. Agent 调 `agent-browser snapshot -i`，从可访问性树读取用户名、密码、验证码输入框与提交按钮的 `@eN` 引用。
5. 识别系统类型（URL/标题/品牌），从本地口令库取默认账号密码，用 `agent-browser fill @eN "..."` 填入。
6. 若存在验证码：`agent-browser eval` 执行 JS 读取验证码图片并转 data URL，管道传给 `captcha_recognize.py --stdin`，把识别结果填入验证码框。
7. `agent-browser click @eN` 提交，随后用 `snapshot`/当前 URL 判断是否进入后台；成功则记录账号口令与证据截图，失败则分析错误文案并尝试下一条或结束。
8. 若工具报参数过长/格式错误，让 Agent 读取 stderr、修改脚本或调用方式（如改为 stdin），重跑验证“自修复”闭环。

## PoC

`SKILL.md` 关键片段：

```markdown
---
name: auto_login
description: >
  Automates login to device/website login pages using agent-browser for browser
  automation, default passwords, form filling, and ddddocr for captcha recognition.
---

## Overview
1. Identify system — infer device/system type from URL, page title, or user hint.
2. Default password — look up references/default_passwords.md.
3. Browser automation — use agent-browser CLI only.
4. Captcha — recognize with ddddocr via scripts/captcha_recognize.py.
5. Success check — infer from URL, snapshot text, or error messages.
```

agent-browser 操作序列（Nacos 默认口令示例）：

```bash
agent-browser open http://target:8848/nacos/ --headed
agent-browser snapshot -i
# 快照返回 e1=用户名 e2=密码 e3=提交
agent-browser fill @e1 "nacos"
agent-browser fill @e2 "nacos"
agent-browser click @e3
agent-browser snapshot -i   # 出现“配置管理/服务管理/权限控制”即成功
agent-browser screenshot nacos-login.png
```

验证码经 stdin 识别（避免 data URL 作为参数过长）：

```python
import sys
import ddddocr

ocr = ddddocr.DdddOcr()
data = sys.stdin.buffer.read()          # --stdin：从管道读取 data URL/图片字节
# 实际脚本需先解析 data URL 的 base64 部分；此处省略解码细节
print(ocr.classification(data).strip())
```

```bash
agent-browser eval '/* 读取验证码 img.src，fetch 后转 data URL 并输出 */' \
  | python scripts/captcha_recognize.py --stdin
```

原文结果：Nacos 2.1.0 使用 `nacos/nacos` 登录成功并进入配置管理；另一个后台站点因 `admin/admin` 本身错误，验证码识别后仍提示 `password_error`，说明该流程可执行但默认口令不命中时不会自动成功。

## 变体与关联

- 变体：把默认口令库替换为按目标指纹（标题、favicon、JS 路径、Server 头）检索的在线/离线知识库，减少人工维护。
- 变体：验证码识别改为 Burp `captcha-killer-modified` + ddddocr 服务，或使用打码平台；Agent 只负责编排请求与回填。
- 变体：把单次默认口令尝试扩展为受控字典轮换，但必须考虑账号锁定、IP 限速与业务影响，避免变成无授权爆破。
- 关联：[[web-generic-auth-captcha-ocr-username-enum-bruteforce]]（ddddocr + captcha-killer 的验证码爆破）；[[web-generic-auth-captcha-ocr-username-enumeration-same-password]]（验证码 OCR + 用户名=口令）；[[ai-security-agent-security-vega-self-evolving-bounty-agent-architecture]]（AI Agent 编排与自进化知识库的同类架构）。
- 关联：Nacos 默认口令进入控制台后，可进一步参考 [[pentest-lateral-movement-nacos-ua-bypass-config-minio-credentials]] 的配置/凭据利用链。

## 检测与防御

- 防御：禁用或强制修改所有出厂/示例账号，首次登录强制改密；对管理后台启用 MFA。
- 防御：验证码使用行为分析、滑块/点选、一次性 token 或风控评分，而不是仅靠简单字符图；对登录失败做账号/IP 双维度限速与锁定。
- 防御：检测浏览器自动化特征（CDP/无头浏览器指纹、异常 UA、固定视口、快照式高频 DOM 查询），对管理后台增加设备指纹与异常登录告警。
- 检测：登录接口出现同一 IP/UA 对多系统默认口令的短时尝试、验证码识别请求与登录请求时间高度相关、成功后立即访问配置管理/服务管理等高权限页面。
- 响应：锁定可疑会话、强制重置默认口令、封禁来源 IP，审计 Nacos 等配置中心的配置变更与服务注册记录。
