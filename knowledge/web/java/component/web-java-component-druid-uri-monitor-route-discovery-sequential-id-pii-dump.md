---
id: web-java-component-druid-uri-monitor-route-discovery-sequential-id-pii-dump
title: Druid 监控台弱口令 → URI 监控导出业务路由 → 自增 ID 接口未授权遍历批量拉取 PII
type: scenario
domain: web
path: web/java/component
technique: druid-uri-monitor-route-discovery-sequential-id-pii-dump
aliases:
- Druid 弱口令到数据泄露
- URL 监控找敏感接口
- Druid URI 监控路由提取
- 自增 ID 接口批量拖数据
- 监控台路由反哺越权
tags:
- java
- druid
- weak-password
- monitoring-console
- route-discovery
- idor
- pii
- enumeration
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T1-24
  verified_at: '2026-11-08T13:24:14+08:00'
  notes: 已对照原文核对：druid弱口令+URI监控三条路由(图19)+customer/120返回PII(图20)支撑；affected_versions不设(1.1.9系参考文章截图版本)；dedup_review对monitor-default-credentials的链路差异成立；卡无sources字段；未验证点：接口未鉴权系原文反推，confidence medium合理
---

## 一句话结论

Druid 监控台用弱口令登录后，其 URI 监控记录了业务前端真实调用过的全部接口路径与参数形态，攻击者据此定位到以自增主键为路径参数、且未做鉴权/越权校验的查询接口（如 `/app/customer/{id}`），直接按 ID 顺序遍历即可逐条取回姓名、手机号、身份证、住址等 PII，规模可达数十万条，把一次监控台弱口令升级为大规模个人信息泄露。

## 原理

- Druid 的 URI 监控（`/druid/uri.json`）与 Web 应用监控是按“实际发生过的请求”统计的，因此它比字典扫描更准：返回的是这套系统真实在用的业务路由，包含前端隐藏的、未在任何菜单暴露的管理/查询接口。
- 这些路由往往以 RESTful 风格把数据库自增主键直接放在路径里（`/app/customer/120`、`/app/work/475`），路径参数即记录序号，意味着数据可按整数连续枚举，不需要知道任何业务标识。
- 提供这类接口的后端通常只校验“是否登录/是否带 token”，甚至完全排除在鉴权拦截器之外（与 Druid 自身被放进鉴权白名单是同一类配置漂移），因此单条查询不做数据归属校验，任意 ID 都能返回他人记录。
- 一旦确认单个 ID 可未授权返回敏感字段，枚举成本仅与请求数成正比；原文以 475→368397 的连续区间取得 30 万+ 条含手机号、姓名、住址、部分身份证的记录，说明接口既无频率限制也无分页上限。
- 该链成立的关键是“监控台弱口令”与“业务接口越权”两个独立缺陷的叠加：前者提供精确的接口清单，后者提供批量取数能力，缺一则只能停在信息泄露或盲扫。

## 触发条件

- 目标 Java 应用启用了 Druid StatViewServlet，且 `/druid/login.html` 从外网可达、使用默认或厂商模板弱口令。
- URI 监控中已积累业务流量（系统在被访问过之后才有数据）。
- 业务侧存在以自增 ID 为参数的查询接口，且未做登录校验或未做数据归属校验。
- 接口没有按 IP/会话的频率限制或总量限制。

## 利用步骤

1. 资产测绘阶段从子域/旁站发现非标准端口上的 `/druid/login.html`（同一企业多个商城/后台常共用一套模板，Druid 常与若依类后台同源部署）。
2. 用弱口令登录监控台（厂商部署模板常见 `ruoyi/123456`、`admin/123456` 之类），确认 Stat Index 可读。
3. 打开 URI 监控（或直接请求 `/druid/uri.json`），按请求次数排序，筛出带数字路径段、名字含 `customer`/`user`/`member`/`order`/`work` 的接口。
4. 抽取候选接口，先用两个相邻 ID 手工请求，比较响应是否返回不同人的 PII、是否要求 token；确认无鉴权后固定请求模板。
5. 用小步长（如 100）先验证 ID 上界与连续性，再对区间做并发遍历，落盘后用手机号/身份证字段去重统计规模。
6. 若响应含 accessToken 或 userId，可进一步用于撞库其他共用同一鉴权外站的商城（同一套统一登录服务的多站点）。

## PoC

```http
GET /druid/index.html HTTP/1.1
Host: target:8081
```

```http
POST /druid/submitLogin HTTP/1.1
Host: target:8081
Content-Type: application/x-www-form-urlencoded

loginUsername=ruoyi&loginPassword=123456
```

登录后取 URI 清单：

```http
GET /druid/uri.json HTTP/1.1
Host: target:8081
Cookie: <druid session>
```

从清单中挑出候选路由后逐条验证：

```bash
for id in 120 121 122; do
  curl -s "http://target:8081/app/customer/$id"
done
```

命中后批量遍历（授权测试，控制速率）：

```bash
seq 475 1000 | xargs -P 5 -I{} curl -s "http://target:8081/app/customer/{}" -o "out/{}.json"
```

单条响应示例（字段为业务返回，实际以目标为准）：

```json
{"code":200,"data":{"customerId":120,"phoneNumber":"138****","realName":"***","cardId":"******","address":"***"}}
```

## 变体与关联

- 变体：URL 监控无数据时，改用 SQL 监控看真实表名与查询条件、或 Session 监控拿活动会话 ID 直接复用登录态。
- 变体：接口不是路径自增 ID，而是 `?id=` 查询参数或 `pageSize` 可被改成极大值，同样可批量取数。
- 关联：Druid 弱口令本身的信息泄露面见 [[web-java-component-druid-monitor-default-credentials]]；若依后台默认口令见 [[pentest-initial-access-ruoyi-default-weak-credentials]]；多商城共用统一鉴权外站导致“一码通杀”见 [[web-generic-auth-sms-login-4digit-code-bruteforce-account-takeover]]。
- 边界：若 Druid 已改强口令/限制来源 IP，或业务接口做了数据归属校验与频率限制，则链断。原文未给出该接口未鉴权的直接证据（未展示去掉 Cookie 的请求），仅以“可连续枚举出 30w 条”反推，故 confidence 标 medium。

## 检测与防御

- 检测：外网对 `/druid/**` 的访问与登录；登录后短时间内拉取 `uri.json`/`sql.json`；业务接口对连续自增 ID 的高频顺序请求（单会话/单 IP 在分钟级覆盖大段 ID）。
- 修复：Druid 改强口令、关闭 StatViewServlet 或仅在运维网段开放；`/druid/**` 必须纳入统一鉴权，不得加入白名单。
- 加固：业务查询接口按当前登录主体做数据归属校验，禁止用自增主键直接定位他人记录；对外暴露的资源标识改用不可枚举的 UUID；对批量遍历做频率限制与告警；敏感字段（身份证、住址）做脱敏返回。
