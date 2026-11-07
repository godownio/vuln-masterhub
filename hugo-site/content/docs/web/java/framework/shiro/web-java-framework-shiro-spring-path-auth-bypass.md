---
id: web-java-framework-shiro-spring-path-auth-bypass
title: Shiro 与 Spring 路径解析差异导致鉴权绕过（分号、编码与 trim）
type: scenario
domain: web
path: web/java/framework/shiro
technique: shiro-path-parser-differential-auth-bypass
tags:
- java
- shiro
- spring
- auth-bypass
- path-parsing
- cve
- access-control
cve:
- CVE-2020-1957
- CVE-2020-11989
- CVE-2020-13933
- CVE-2020-17523
severity: high
confidence: medium
status: verified
created: '2026-11-04'
updated: '2026-11-05'
affected_versions: 'CVE-2020-1957: Shiro<1.5.2；CVE-2020-11989: Shiro<1.5.3；CVE-2020-13933: Shiro<1.6.0；CVE-2020-17523: Shiro<1.7.1（均需 Spring 应用仅用 Shiro 做鉴权）'
verification:
  verified_by: verifier-V8
  verified_at: '2026-11-05T00:41:05+08:00'
  notes: 已对照原文核对四个 CVE 的版本区间与 POC（..;/、;/、%25%32%66/%252f、%3b、%20/%08/%09/%0a/%0d）及 Spring 与 Shiro 解码/trim 差异；原文仅给 POC 列表、未逐条复现，confidence medium 合理；affected_versions 已按原文设置。
url: /docs/web/java/framework/shiro/web-java-framework-shiro-spring-path-auth-bypass/
draft: false
kb_aliases:
- Shiro 权限绕过
- CVE-2020-1957
- CVE-2020-11989
- CVE-2020-13933
- CVE-2020-17523
- 分号绕过 Shiro
---

## 一句话结论

Shiro 做鉴权、Spring 做路由时，两者对 `;`、URL 编码和空白字符的解析/解码次数不同；攻击者构造一个 Shiro 认为“未受保护”、Spring 却路由到受保护接口的路径，即可未授权访问管理端点。

## 原理

- Shiro 的过滤器链按请求路径匹配 `filterChainDefinitionMap`，Spring MVC 则用自己的路径解析规则选择 controller；两者只要对同一原始路径得出不同“规范路径”，就会出现鉴权与路由的错位。
- `;` 在 Servlet 规范中是路径参数分隔符。Shiro/部分 Spring 版本在匹配时会保留或截断 `;` 后的内容，而另一侧会去掉 `;` 及其后缀，导致 Shiro 匹配到放行规则、Spring 实际进入受保护 controller。
- 编码差异同理：Spring 可能持续解码直到稳定（`%25%32%66` → `%2f` → `/`），Shiro 只解码一次，于是 Shiro 看到的是编码后的放行路径，Spring 看到的是解码后的受保护路径。
- 空白 trim 差异：Shiro 的 Ant 匹配可能对路径做 trim，把 `/admin/%20` 归一化为 `/admin/` 后判定为无需鉴权，而 Spring 仍把它路由到 `/admin` 相关接口。
- 因此根因不是单个 payload，而是“鉴权组件与路由组件的路径规范化不一致”。

## 触发条件

- Spring 应用只使用 Shiro 做鉴权（典型 Shiro + Spring/Spring Boot 组合）。
- 目标版本落在对应 CVE 的受影响区间。
- 受保护接口可通过路径变体到达（如 `/admin`、`/admin/`、带 context-path 的部署）。
- 应用未额外使用 Spring Security 等方法做二次鉴权。

## 利用步骤

1. 确认目标使用 Shiro：`rememberMe=deleteMe` 特征、登录跳转、Shiro 错误页。
2. 找到受保护路径（如 `/admin`），未登录直接访问应被重定向/拒绝。
3. 按目标版本尝试对应路径变体，观察是否直接返回受保护内容：
   - `..;/` 或 `;` 插入；
   - 双重编码；
   - 尾部空白字符。
4. 成功后访问管理功能，完成越权操作。

## PoC

按 CVE 分类的路径变体：

```text
# CVE-2020-1957  Shiro < 1.5.2（Spring < 2.3 的 ..;/ 变体）
/xxx/..;/admin/ctfer
/;/admin/ctfer
/admin;/ctfer          # Spring 全版本

# CVE-2020-11989  Shiro < 1.5.3
/admin/a%25%32%66a
/admin/a%252fa          # 期望解码为 /admin/a%2fa
/;/context/admin/user   # context-path 非根时

# CVE-2020-13933  Shiro < 1.6.0
/admin/%3bctfer

# CVE-2020-17523  Shiro < 1.7.1
/admin/%20
/admin/%08  /admin/%09  /admin/%0a  /admin/%0d
```

以未登录身份请求这些路径，若返回管理页面而非登录页，即绕过成功。`%20` 系列在 Spring Boot + Tomcat 下可能因 400 失败，需要按环境尝试。

## 变体与关联

- 变体：`;` 可放在路径任意段；编码次数可叠加；不同 servlet 容器/Spring 版本对 `;` 与 `%2f` 处理不同，需按版本选择。
- 关联：[[web-java-framework-shiro-550-hardcoded-key-deserialization]]（鉴权绕过可扩大 RCE 入口）；[[web-java-framework-shiro-721-padding-oracle]]（同属 Shiro 攻击面）。
- 边界：原文只给出 POC 列表与原理，未提供逐条复现截图；具体变体是否成功取决于 Spring/容器版本与 Shiro 过滤器配置，置信度定为 medium。

## 检测与防御

- 检测：请求路径含 `;`、`%3b`、`%25`、尾部空白/控制字符；同一会话对受保护路径的变体探测；Shiro 放行但 Spring 路由到敏感 controller 的日志差异。
- 防御：升级 Shiro 到对应修复版本（1.5.2/1.5.3/1.6.0/1.7.1 及以上）；在 Spring 层增加独立鉴权；统一路径规范化（拒绝含 `;`、控制字符、重复编码的请求）；对受保护路径使用精确匹配而非前缀/通配。
