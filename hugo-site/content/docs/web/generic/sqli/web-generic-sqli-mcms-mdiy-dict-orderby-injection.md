---
id: web-generic-sqli-mcms-mdiy-dict-orderby-injection
title: MCMS 5.2.4 /mdiy/dict/listExcludeApp orderBy 参数直拼 ${}：未授权 ORDER BY 注入 updatexml 报错注入
type: scenario
domain: web
path: web/generic/sqli
technique: mybatis-orderby-dollar-brace-unauth-sqli
tags:
- web
- java
- mcms
- mingsoft
- sqli
- mybatis
- order-by
- error-based
- unauth
cve: []
severity: high
confidence: medium
affected_versions: MCMS（MingSoft CMS）5.2.4（原文审计版本；其他版本未验证）
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V223
  verified_at: '2026-11-07T06:48:19+08:00'
  notes: 已通读原文并逐张核对本地61张图：mdiy orderBy SQLi 章节的远程 xz.aliyun.com 截图未包含在本地 img，卡片依据正文（${} 包裹 order by、只需 orderBy 参数、直接调用无过滤、未授权、GET /mdiy/dict/listExcludeApp?orderBy=1 or updatexml(1,concat(0x7e,user(),0x7e),1)）撰写，正文与卡一致；confidence=medium 合理。dedup_review 的 --force 理由成立：FastCMS 用 MyBatis-Plus orderByDesc+customSqlSegment、CordysCRM 用 departmentIds 拼 order by field，本卡是 MCMS XML ${orderBy}，产品/入口/实现均不同。未验证点：报错回显为预期结果、远程截图未本地留存；PoC未复跑；frontmatter无 sources/source_url；affected_versions按原文审计版本MCMS 5.2.4标注。
url: /docs/web/generic/sqli/web-generic-sqli-mcms-mdiy-dict-orderby-injection/
draft: false
kb_aliases:
- MCMS SQL 注入
- MingSoft CMS 注入
- /mdiy/dict/listExcludeApp
- orderBy 注入
- MyBatis ${orderBy}
- updatexml 报错注入
---

## 一句话结论

MCMS 的 `/mdiy/dict/listExcludeApp` 接口把请求参数 `orderBy` 原样传给 Mapper XML 中 ORDER BY 位置的 `${orderBy}` 文本替换，既没有白名单也没有过滤，且该路由不带 `/ms` 管理前缀、可未授权访问；用 `orderBy=1 or updatexml(1,concat(0x7e,user(),0x7e),1)` 即可通过 MySQL 报错注入回显数据库用户。

## 原理

- **注入点**：MyBatis 的 `#{}` 走预编译占位符，`${}` 是字符串直接替换。ORDER BY 后面需要列名/表达式，很多项目误用 `${orderBy}` 拼接，导致用户输入进入 SQL 语法层。
- **代码路径**：`/mdiy/dict/listExcludeApp` 的 Controller 只把 `orderBy` 取出来传给 Service/Mapper；XML 中类似 `order by ${orderBy}`，没有列名白名单或正则校验。
- **未授权入口**：`/mdiy/**` 路由不带 `${ms.manager.path}`（`/ms`）前缀，因此不经过后台登录过滤器；文章明确该点是“页面上找不到功能点、未授权的点”。
- **报错注入**：MySQL 的 `updatexml(1,concat(0x7e,user(),0x7e),1)` 在第二个参数不是合法 XPath 时抛错，错误信息包含 `~root@localhost~`；`orderBy=1 or updatexml(...)` 使 ORDER BY 表达式既合法又触发函数。
- **为什么成立**：ORDER BY 不能用 `?` 占位符，一旦拼接且无白名单，输入就是 SQL 表达式的一部分；`or` 让排序条件恒真，同时执行报错函数。

## 触发条件

- MCMS 5.2.4（或存在同类 `${orderBy}` Mapper 的版本），数据库为 MySQL（`updatexml` 可用）。
- `/mdiy/dict/listExcludeApp` 未授权可达。
- 目标未对 `orderBy` 做列名白名单；WAF 未拦截 SQL 关键字。

## 利用步骤

1. 直接访问 `/mdiy/dict/listExcludeApp`，确认无需登录返回字典数据。
2. 构造 `orderBy=1 or updatexml(1,concat(0x7e,user(),0x7e),1)`，URL 编码后发送。
3. 观察响应中的 SQL 报错，回显 `~root@localhost~` 等数据库信息。
4. 若回显长度受限（updatexml 最多约 32 字符），改用 `extractvalue`、`substring` 分段、布尔/时间盲注。
5. 进一步可读取当前库表、管理员哈希或写文件（取决于数据库权限）。

## PoC

```http
GET /mdiy/dict/listExcludeApp?orderBy=1%20or%20updatexml(1,concat(0x7e,user(),0x7e),1) HTTP/1.1
Host: target:8081
Accept: application/json
```

响应中若出现类似 `XPATH syntax error: '~root@localhost~'` 即注入成功。文章给出的原始 payload 为：

```text
/mdiy/dict/listExcludeApp?orderBy=1 or updatexml(1,concat(0x7e,user(),0x7e),1)
```

## 变体与关联

- **同项目另一处 ${}**：`IContentDao.xml` 的 `find_in_set(${categoryId},'CATEGORY_PARENT_IDS')` 也是 `${}` 拼接，可经无前缀 `/cms/...` 列表接口未授权触达；原文只给出代码位置与未授权访问，未给出该点的注入 payload，故未单独成卡。
- **ORDER BY 注入通用手法**：[[web-generic-sqli-java-identifier-table-order-by-injection]]、[[web-generic-sqli-mybatis-dollar-brace-injection]]、[[web-generic-sqli-fastcms-article-list-orderby-injection]]。
- **未授权根因**：[[web-java-component-mcms-dual-route-prefix-auth-bypass]]。
- **变体**：MySQL 版本不支持 updatexml 时用 `extractvalue`；过滤关键字时用大小写/注释/编码绕过；无回显时用时间盲注。

## 检测与防御

- **检测**：`orderBy`、`sort` 等参数出现 SQL 关键字、函数名、空格/注释；响应出现 XPath/语法错误；同一接口无会话也能返回数据。
- **防御**：ORDER BY 列名使用枚举/白名单映射，禁止 `${}` 接用户输入；对 `/mdiy/**` 纳入认证；数据库账号最小权限；WAF 拦截报错函数关键字（只能缓解）。
