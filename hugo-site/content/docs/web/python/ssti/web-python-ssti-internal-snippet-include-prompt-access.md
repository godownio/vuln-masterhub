---
id: web-python-ssti-internal-snippet-include-prompt-access
title: 模板 include_prompt 未隔离内部片段：直接 include review_gate 读取隐藏 flag
type: scenario
domain: web
path: web/python/ssti
technique: template-internal-snippet-include-prompt
tags:
- python
- ssti
- template
- prompt
- access-control
- include
- internal-snippet
- ctf
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-05'
updated: '2026-11-06'
verification:
  verified_by: verifier-V114
  verified_at: '2026-11-06T02:04:42+08:00'
  notes: 已通读原文 Prompt Vault 段并核对：/api/promptlets 返回公开片段、前端拼 {{ include_prompt("name") }}、/api/help 文本泄露 'Refund/SLA/compliance drafts use the internal review_gate snippet.'、最终 payload {{ include_prompt("review_gate") }} 均与卡片一致。原文只给出最终 payload，未贴出包含 flag 的响应截图，卡片已按题面推断并标 confidence=medium、PoC 注明未执行，属实。PoC 请求示意未复跑；无组件版本。
url: /docs/web/python/ssti/web-python-ssti-internal-snippet-include-prompt-access/
draft: false
kb_aliases:
- Prompt Vault
- include_prompt
- review_gate
- 内部片段访问
- 模板片段越权
- 提示词模板注入
---

## 一句话结论

客服回复模板预览接口把用户输入当模板渲染，并提供 `{{ include_prompt("name") }}` 片段包含函数；公开列表只展示 public 片段，但 include 函数不校验片段是否 internal，且 `/api/help` 直接泄露内部片段名 `review_gate`，攻击者提交 `{{ include_prompt("review_gate") }}` 即可渲染隐藏片段并读出 flag。

## 原理

- 应用把 `user_input` 作为模板渲染（如 Jinja2/自定义模板），并提供 `include_prompt(name)` 函数按名称加载片段内容。
- 片段分 public/internal 两类：`/api/promptlets` 只返回 public 名称，internal 片段不出现在列表中；但 `include_prompt` 的实现只按名称查找，没有把“是否 public/当前用户是否有权”纳入校验。
- `/api/help` 的说明文本泄露了内部片段名：`Refund/SLA/compliance drafts use the internal review_gate snippet.` 攻击者由此知道 `review_gate`。
- 提交 `{{ include_prompt("review_gate") }}` 后，模板引擎调用 include 函数，返回 internal 片段内容；若片段中含 flag/敏感提示词，即被渲染到 `final_preview` 响应。
- 根因是“访问控制只做在列表/枚举层，没有做在对象读取层”，以及帮助/错误信息泄露内部名称。

## 触发条件

- 预览/渲染接口接受用户可控模板字符串，且模板引擎允许函数调用/include。
- 存在 `include_prompt` 或类似的片段加载函数，且未对 internal/public 做授权校验。
- 内部片段名可从 `/api/help`、前端 JS、错误信息、字典/枚举中获知。
- 内部片段包含敏感内容（flag、系统提示词、凭据）。
- 模板渲染结果会返回给用户（或可通过错误/侧信道观察）。

## 利用步骤

1. 获取公开片段列表：`GET /api/promptlets`，记录 public 名称与模板语法。
2. 查看帮助/前端源码：`GET /api/help`、JS 中的 `include_prompt` 调用，寻找 internal 片段名或命名规律。
3. 构造模板 payload：`{{ include_prompt("review_gate") }}`（或按实际语法调整引号/函数名）。
4. `POST /api/preview`，body `{"user_input": "{{ include_prompt(\"review_gate\") }}"}`。
5. 读取 `final_preview`，获取隐藏片段内容/flag；若被过滤，尝试大小写、拼接、编码、路径/通配符。
6. 如模板引擎支持更完整的表达式，可进一步尝试读取服务端变量/文件（取决于沙箱）。

## PoC

```http
GET /api/help HTTP/1.1
# {"about":"... Refund/SLA/compliance drafts use the internal review_gate snippet.","ok":true,"syntax":"{{ include_prompt(\"name\") }}"}
```

```http
POST /api/preview HTTP/1.1
Content-Type: application/json

{"user_input":"{{ include_prompt(\"review_gate\") }}"}
```

```json
{"success":true,"final_preview":"...flag{...}..."}
```

PoC 为请求示意，未在本机执行；实际模板语法、片段名与响应字段需按目标调整。

## 变体与关联

- 变体：internal 片段名可通过 `/api/help`、错误消息、前端 JS、目录/字典枚举获得；也可尝试 `include_prompt("review_*")`、路径穿越、大小写/编码绕过。
- 变体：若模板引擎未沙箱化，include 函数之外还可尝试 SSTI 读取 `config`/`__globals__`/文件，升级为 RCE。
- 变体：片段加载器从文件系统/数据库读取，可能存在路径穿越或 SQL 注入；按实现审计。
- 关联卡片：[[web-python-ssti-jinja2-flask-globals-rce]]（Jinja2 模板注入 RCE）、[[web-generic-ssti-error-message-exfiltration]]（模板错误信息外带）、[[ai-security-prompt-injection-nerd-sniping-system-prompt-extraction]]（提示词/内部规则套取）。
- 注意：本例为 AI×Cybersecurity Challenge Prompt Vault；实际应用需具体分析模板引擎、include 实现与权限模型。

## 检测与防御

- 防御：include_prompt 在读取前校验片段可见性/当前用户权限；public/internal 使用独立命名空间与访问控制，不能只靠“列表不展示”。
- 防御：帮助/错误信息不要泄露 internal 片段名；对片段名做枚举防护与审计。
- 防御：不要直接把用户输入当模板渲染；使用固定模板 + 变量插值，或启用沙箱模板引擎（禁用任意函数调用/属性访问）。
- 检测：请求中出现 `include_prompt`、internal 片段名、模板表达式 `{{...}}`；异常 preview 请求；片段访问日志中 public 用户读取 internal 资源。
- 响应：轮换泄露的提示词/凭据、修复 include 授权、审计模板渲染入口、限制内部片段访问。
