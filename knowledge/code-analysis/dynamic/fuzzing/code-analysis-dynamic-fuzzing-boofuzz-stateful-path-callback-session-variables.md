---
id: code-analysis-dynamic-fuzzing-boofuzz-stateful-path-callback-session-variables
title: boofuzz 有状态序列模糊测试：用 connect 的 callback 与 session_variables 把上一个请求的响应喂进下一个请求
type: scenario
domain: code-analysis
path: code-analysis/dynamic/fuzzing
technique: boofuzz-stateful-path-callback-session-variables
aliases:
- boofuzz 有状态 fuzz
- boofuzz callback
- boofuzz session_variables
- ProtocolSessionReference
- boofuzz 登录态 fuzz
tags:
- boofuzz
- fuzzing
- protocol-fuzzing
- stateful
- callback
- python
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-T2-3W8
  verified_at: '2026-11-09T02:35:27+08:00'
  notes: 已对照原文核对：Path 深度优先、only fuzz_node 变异/non-fuzznode 用默认值（transmit_normal/transmit_fuzz）、callback 在前后 node 发包之间调用、session.last_send/last_recv、receive_data_after_each_request 默认 True 故回调内不应再 sock.recv、test_case_context.session_variables 与 ProtocolSessionReference 的 render 取值逻辑，均与正文文字及 Python 示例对应。本次核对未读取图片；正文 23 张截图中的源码片段与调试输出细节未核对，卡内描述限于正文文字已明确的部分；卡内 PoC 是按正文示例改写的登录态演示，非原文原样 PoC。dedup：t2_card 判 duplicate 但 top 为草稿自身（1.000），排除自身后最高外部候选为同篇另一张 boofuzz 卡（0.114，互补关系）与无关的 WordPress REST permission_callback 卡（0.093），非同一条链
---

## 一句话结论

boofuzz 的 `Path` 里**只有最后一个 Node（fuzz_node）会被变异，前面的 Node 一律用默认值发送**，因此"先登录再访问需要登录的接口"这类场景必须靠 `session.connect(a, b, callback)` 的回调：在回调里用 `session.last_recv` 取上一个请求的原始响应，用 `test_case_context.session_variables[name] = value` 写进变量，配合原语 `default_value=ProtocolSessionReference(name=...)`，让下一个请求的字段在 render 时动态取到登录返回的 Cookie/Token。

## 原理

- **为什么必须用回调**：Session 用深度优先遍历请求树生成 Path，路径上的 non-fuzznode 走 `transmit_normal` 直接发送默认值、不参与变异；fuzznode 走 `transmit_fuzz`。回调解在这两步之间、且在后一个 Node 发包之前被调用，是唯一能拿到"前一个响应"并影响"下一个请求内容"的时机。
- **为什么 `session.last_recv` 里已经有数据**：non-fuzznode 发包后默认会 `recv`（`Session(receive_data_after_each_request=True)` 的默认行为），收到的原始字节存进 `session.last_recv`；发送出去的原始字节存进 `session.last_send`。所以回调里**不该再自己调 `socket.recv()`**——很多示例在回调里 `sock.recv()` 拿不到数据，就是因为数据已经被 Session 收走了。fuzznode 默认不 `recv`（变异包容易超时），但 fuzznode 是路径末节点，后面没有回调，也不需要。
- **为什么用 `session_variables` 而不是直接改原语**：`test_case_context.current_message.names[qualified_name]._default_value = ...` 也能改，但这是绕过 API 直接改私有字段，且只影响"使用 default_value 的那个对象实例"。`ProtocolSessionReference` 是官方提供的通道：原语 render 时若发现 `default_value` 是 `ProtocolSessionReference`，就从 `test_case_context.session_variables[name]` 取值，回调只需写一个键值，不接触原语内部结构。
- **为什么这是"有状态"**：变异只作用在末节点，而末节点的很多字段（Cookie、CSRF token、会话 ID）必须由前一个响应决定；如果没有这条通道，fuzz 会话根本进不到被测逻辑，测出来的都只是鉴权失败分支。

## 触发条件

- 被测目标是有状态协议/接口：后续请求依赖前一个请求返回的会话凭据、ID 或一次性 token。
- 用 boofuzz 的 `Session` + `Target`（如 `TCPSocketConnection`）组织多请求；Request 之间已用 `session.connect(prev, next, callback)` 连成 Path。
- 回调里能解析出需要复用的字段（正则、JSON、固定偏移均可）；解析失败应显式放弃本轮或回退默认值，避免把脏值灌进后续请求。

## 利用步骤

1. 定义请求：登录请求 `req1`（字段用 `s_static`/`s_group` 定义），业务请求 `req2`。
2. 把需要被前一个响应填充的字段，`default_value` 设为 `ProtocolSessionReference(name="ref_data", default_value="<兜底值>")`。
3. 用 `session.connect(s_get("req1"))` 挂到根节点，再 `session.connect(s_get("req1"), s_get("req2"), test_case_callback)` 注册回调。
4. 回调里用 `session.last_recv` 取 `req1` 的响应原文，正则抽出 Cookie/SessionID，写入 `test_case_context.session_variables["ref_data"]`。
5. 调试期在回调里把 `session.last_send` / `session.last_recv` 落盘，确认序列与解析结果符合预期，再关闭落盘（否则 fuzz 一轮就写满磁盘）。
6. 启动 `session.fuzz()`；若需要控制变异范围，注意默认启用组合变异（不指定 `max_depth`），见关联卡。

## PoC

```python
from boofuzz import *

def login_callback(target, fuzz_data_logger, session, test_case_context, *args, **kwargs):
    # 上一个请求的原始收发内容已由 Session 存好，不要再自己 recv
    resp = session.last_recv or b""
    m = re.search(rb"SESSIONID=([0-9a-f]+)", resp)
    if m:
        # 写入变量，供下一个 Node 的 ProtocolSessionReference 原语在 render 时读取
        test_case_context.session_variables["session_id"] = m.group(1).decode()

s_initialize(name="login")
s_static("POST /login HTTP/1.1\r\n")
s_static("Host: 127.0.0.1\r\n")
s_static("Content-Length: 13\r\n\r\n")
s_string("user=admin&p", name="body")   # 登录请求的变异点

s_initialize(name="profile")
s_static("GET /profile HTTP/1.1\r\n")
s_static("Host: 127.0.0.1\r\n")
s_static("Cookie: SESSIONID=")
s_static(ProtocolSessionReference(name="session_id", default_value="0"), name="sid")
s_static("\r\n\r\n")

session = Session(target=Target(connection=TCPSocketConnection("127.0.0.1", 8080)))
session.connect(s_get("login"))
session.connect(s_get("login"), s_get("profile"), login_callback)
session.fuzz()
```

```text
要点：
1) 只有 profile 这个末节点会被变异，login 每次用默认值发送；
2) login 的响应由 Session 自动 recv 进 last_recv，回调里直接读；
3) session_variables 里的 session_id 会替换掉 profile 请求里 ProtocolSessionReference 处的兜底值 "0"。
```

## 变体与关联

- 取响应数据的其他写法：`session.last_recv` 只在"开启了 receive_data_after_each_request"时有值；若关闭该选项，需要在回调里自行 `target.recv()` 并维护缓冲。也可以用 `fuzz_data_logger` 记录原始字节做离线解析。
- 影响下一个请求的另一种写法：`test_case_context.current_message.names["req2.Host-Line-Value"]._default_value = ...`——能生效但直接改私有属性，且要求 qualified_name 精确匹配（`<request>.<primitive>`），重构易失效。
- 关联：`[[code-analysis-dynamic-fuzzing-boofuzz-mutation-single-primitive-maxdepth-group]]`（同一工具的另一半：变异粒度与组合次数）；同目录下 libFuzzer/AFL 系列卡偏无状态语料变异，本卡解决的是"会话状态"这一层。
- 边界：若目标会话凭据有一次性/时间窗限制（token 一次有效），`req1` 每个 Path 都要重发一次，且 fuzz 速率受会话创建成本限制；若响应为二进制协议，需要按协议解析而非正则；若 `req1` 本身也需要变异（例如同时 fuzz 登录字段），要把它放到独立 Path 里当末节点，不要和 `req2` 放在同一条 Path 内混用。

## 检测与防御

- 检测（对被测方/防守视角）：同源 IP 出现高频"登录成功 + 立即访问受保护接口"的成对请求序列，会话 ID 不断变化；登录接口成功率异常高但请求体高度相似——典型的有状态 fuzz 特征。
- 防御：对登录/会话创建做速率限制与账号锁定；一次性 token 绑定 IP/UA 并短时过期；对同一会话的请求序列做异常频率检测；协议层对畸形字段长度与编码做严格校验，让 fuzz 尽早落到参数校验而非崩溃。
