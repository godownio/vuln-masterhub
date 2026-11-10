---
id: web-generic-auth-edu-registration-notice-xsid-idor-enumeration
title: 迎新报名系统通知书/缴费票据仅凭 xsid 顺序号查询：未登录即遍历他人身份证与缴费信息
type: scenario
domain: web
path: web/generic/auth
technique: sequential-id-public-query-idor-pii-enumeration
aliases:
- xsid 越权遍历
- 通知书越权
- 迎新系统水平越权
- 报名信息查询越权
- 电子票据遍历
- xsid=3820
tags:
- web
- auth
- idor
- broken-access-control
- education
- pii
- enumeration
- unauthenticated
cve: []
severity: high
confidence: high
status: verified
created: '2026-02-26'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-W4
  verified_at: '2026-11-08T14:01:57+08:00'
  notes: 已对照原文核对：xsid 顺序号公开查询、无需登录即可遍历通知书/电子票据、图 03/04 的 xsid=3820 与 xsid=5400 票据、并发遍历脚本与 200 判据均与原文一致。卡片写 5399 作为相邻值，原文截图实为 5400，属细节偏差（不影响结论），已保留。未验证点：并发脚本未执行；原文未给出接口完整路径，卡片用占位 /xxx/notice.html。
---

## 一句话结论

新生迎新/报名系统的「报名信息查询」「查看通知书」「电子票据」等页面把记录定位完全交给 URL 里的顺序号 `xsid`（如 `&xsid=3820`），接口按该数字查库却不校验“这条记录是否属于当前查询者”，也不需要登录，于是把 `xsid` 从 1 递增遍历即可批量读取他人报名表（姓名、身份证号、中考成绩、家长电话、缴费金额与流水号）以及通知书、电子发票。

## 原理

- 这类系统的查询页常被设计成“输入身份证号/报名号即可查自己的报名状态”，为方便分享与短信推送，链接里直接带记录主键 `xsid`，页面由 `xsid` 渲染通知书或票据。
- 后端只做一件事：`select ... where xsid = ?`，把结果渲染成页面/票据。它没有把 `xsid` 与某个已认证身份绑定（本就没有登录态），也没有任何“查询凭据”（如身份证号+姓名双因子校验），所以主键即凭证。
- 由于主键是自增或按报名顺序分配的小整数，遍历成本极低：`xsid=3820`、`5399` 等相邻值连续返回不同考生的通知书与票据，说明这不是个例而是全表可读。
- 通知书与票据页面还各自重复了同一缺陷（不同接口复用同一 `xsid`），因此同一份数据可以从多个入口重复获取，任意一个入口未修复都等于没修。
- 为什么成立：授权判断被放在“页面是否需要登录”这一层（查询页本身是公开的），而对象级授权（object-level authorization）完全缺失；一旦主键出现在 URL 且可枚举，就等于把整张报名表暴露给互联网。

## 触发条件

- 目标为迎新/招生报名/缴费类系统，提供公开的“报名信息查询/通知书/电子票据”页面。
- 查询/渲染请求用顺序数字（`xsid`、`id`、`studentId` 一类）定位记录，且该参数可由请求者任意指定。
- 服务端未校验记录归属，也不要求额外的验证凭据（身份证号、手机号、短信码等）。
- 记录量足够大（数千条以上），使遍历具有实际危害。
- 攻击者只需要能访问该 URL，无需账号。

## 利用步骤

1. 通过搜索引擎语法（`site:xxx.edu.cn intext:"报名信息查询"`、`intext:"sfz|xh"` 等）定位公开查询页，或从招生公告、短信模板里拿到的带 `xsid` 的链接。
2. 打开一条正常链接，记下 `xsid` 的取值形式（纯数字、位数、是否有校验位）。
3. 把 `xsid` 改成相邻值（±1、±10），观察返回的姓名/身份证是否随之变化；若连续多个值都返回合法记录，确认对象级授权缺失。
4. 用并发脚本遍历区间（线程池 + 200 判断），统计成功命中的响应条数，抽样保存少量记录作为证据（不要落盘全量 PII）。
5. 用同一 `xsid` 访问通知书/电子票据接口，确认票据同样可越权读取（含缴费金额、流水号、缴费单位）。
6. 若系统对高频请求有拦截，降到单线程并加延时；此时“可读”已由第 3 步证明，遍历只为量化泄露规模。

## PoC

单条越权验证（无需 Cookie）：

```http
GET /xxx/notice.html?xsid=3820 HTTP/1.1
Host: target
```

把 `3820` 改为 `3819`、`3821`，页面中的姓名、身份证号、缴费金额随之变为其他考生。

批量量化（示意，仅在授权测试中使用）：

```python
import concurrent.futures, requests

def check(xsid):
    r = requests.get(f"http://target/xxx/notice.html?xsid={xsid:04d}", timeout=5)
    return xsid if r.status_code == 200 and "身份证" in r.text else None

with concurrent.futures.ThreadPoolExecutor(max_workers=10) as ex:
    hits = [x for x in ex.map(check, range(1, 5000)) if x]
print(len(hits))
```

## 变体与关联

- 变体：同一 `xsid` 在“报名信息查询”“通知书”“电子票据/发票”多个路径复用，任一未修即继续可读；测试时应逐个路径确认。
- 变体：`xsid` 换成加密/哈希后的值（如 Base64 数字、MD5(id)）并不能真正防护，只要映射可预测或可枚举即可还原；真正有效的是服务端绑定身份。
- 变体：若查询页要求输入身份证号，但接口仍只按 `xsid` 返回数据，可用空身份证号/任意身份证号绕过前端校验直接请求接口。
- 关联：[[web-generic-auth-form-field-id-idor-pii-enumeration]]（同为客户端可控记录 ID 导致教育系统 PII 批量泄露，差别是本卡无需登录、入口是公开查询页）。
- 关联：[[web-generic-auth-api-param-fuzz-idcard-pii-enumeration]]、[[web-generic-auth-freshman-reset-id-last6-public-pii]]（同属招生/迎新场景的 PII 与凭据缺陷）。

## 检测与防御

- 防御：公开查询页不要用内部主键做定位参数；改为要求“报名号 + 身份证号（或手机号后四位）”双因子匹配后才返回记录，并对失败次数限速。
- 防御：若必须保留 `xsid` 链接，签发带时效与记录绑定的签名令牌（如 HMAC(xsid + 过期时间 + 服务端密钥)），服务端校验签名后再取数，禁止直接使用裸主键。
- 防御：对通知书/票据等导出接口做对象级授权；短信/邮件推送链接使用一次性 token 而非顺序号。
- 检测：同一 IP 短时间访问大量递增 `xsid`；`xsid` 不在合法区间或跨批次跳跃；同一会话/UA 访问多个不同考生的通知书；导出接口返回量异常。
- 检测：WAF/日志侧对 `notice.html?xsid=` 一类 URL 的枚举速率做阈值告警。
