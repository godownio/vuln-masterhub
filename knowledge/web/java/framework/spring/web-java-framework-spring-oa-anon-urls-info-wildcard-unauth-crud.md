---
id: web-java-framework-spring-oa-anon-urls-info-wildcard-unauth-crud
title: 文都 OA 匿名白名单 `/info/**` 通配放行：未授权读取 288 条员工 PII 并任意增删改
type: scenario
domain: web
path: web/java/framework/spring
technique: anon-urls-wildcard-prefix-unauth-controller-crud
aliases:
- 文都 OA 未授权
- anonUrls 通配符匿名
- /info/emp 未授权员工信息
- AntPathMatcher 匿名白名单
- SecurityFilter 白名单绕过
tags:
- java
- spring-boot
- spring-mvc
- filter
- anon-urls
- authentication-bypass
- unauthorized-access
- pii
- information-disclosure
- crud
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V246
  verified_at: '2026-11-07T12:57:43+08:00'
  notes: 已对照原文及14张图核对：application.yaml oa.anonUrls 含 /info/**、SecurityFilter AntPathMatcher 短路、GET /info/emp 返回 total 288、POST /info/emp 新增李四(00289/00290)、DepController POST/PUT/DELETE 映射均一致；未验证点：DepController 增删改与员工其他 CRUD 未逐条实测（原文只实测 GET/POST），JWT 与头像上传未成链。
---

## 一句话结论

文都 OA（yongjannes/OA）把 `/info/**` 写进 `oa.anonUrls` 匿名白名单，`SecurityFilter` 用 `AntPathMatcher` 匹配到前缀后直接 `filterChain.doFilter()` 放行；由于全项目只有这一个过滤器，`/info/emp`、`/info/dep` 等 Controller 没有任何二次鉴权，未登录即可读取 288 条员工姓名/性别/生日/部门等 PII，并可通过 POST/PUT/DELETE 任意新增、修改、删除员工与部门数据。

## 原理

- **匿名配置来自外部属性**：`AnonUrls` 用 `@ConfigurationProperties(prefix = "oa")` 绑定 `application.yaml` 的 `oa.anonUrls`，值为 `/security/login`、`/t`、`/res/**`、`/info/**` 等。`/info/**` 本意可能只是放行某个信息接口，但通配符覆盖了整个 `/info` 命名空间下的所有业务 Controller。
- **过滤器短路即直达控制器**：`SecurityFilter.doFilter` 先读取 `anonUrls`，用 `AntPathMatcher.match(item, request.getServletPath())` 逐条匹配；命中即 `filterChain.doFilter(request, response)` 并 `return`，不再执行后面的 token 校验。项目只有一个 filter，没有 Spring Security、HandlerInterceptor 或 AOP 兜底，所以请求直接进入 Controller。
- **控制器没有方法级授权**：`EmployeeController` 类级映射 `@RequestMapping("/info/emp")`，`DepController` 同在 `com.sf.demo.api.info` 包下；代码中未见 `@PreAuthorize`/角色判断，匿名放行等于完全授权。
- **危害落地**：员工接口返回 `e_id`、`e_name`、`e_sex`、`e_birth`、`e_status`、`d_id`、`d_name` 等字段（原文响应一次返回 `total: 288` 条分页数据）；同命名空间下还有增删改接口，`POST /info/emp` 实测插入新员工成功，数据库出现新记录，说明不仅是读泄露，还可篡改业务数据。
- **为什么容易漏**：审计时只关注登录接口是否正常，而不逐条核对匿名通配符覆盖的实际 Controller 映射；`/info/**` 这种“看起来像公共信息”的前缀会把整个模块带出鉴权。

## 触发条件

- 目标使用该 OA 代码且 `application.yaml` 保留 `oa.anonUrls` 中的 `/info/**`（默认配置即如此）。
- 后端端口可达（原文为 `9999`；前端开发端口 `808` 也可能反向代理到后端）。
- 不需要任何账号或 token；`SecurityFilter` 在匿名路径上直接放行。
- 请求为普通 HTTP/JSON，无额外签名或验证码。

## 利用步骤

1. 直接请求员工列表：`GET http://<host>:9999/info/emp`（可分页参数）。响应 `{"success":true,"code":200,...,"total":288,"list":[...]}`，拿到员工 ID、姓名、性别、出生日期、在职状态、部门 ID/名称等 PII。
2. 新增员工（无需登录）：`POST http://<host>:9999/info/emp`，JSON 体如 `{"e_name":"李四","e_sex":2,"e_birth":"1992-05-15","d_id":1}`，返回 `code:200`；数据库中可看到新增记录。
3. 同命名空间下的部门接口同样匿名：`GET /info/dep` 读取部门；`POST /info/dep` 新增、`PUT /info/dep` 修改、`DELETE /info/dep/{id}` 或 `DELETE /info/dep`（传 ID 数组）删除；`PUT /info/dep/{id}/{status}` 改状态。原文截图给出了这些映射，未逐一复现全部方法。
4. 结合泄露的员工/部门结构，可进一步枚举组织架构、批量拉取全部 PII，或删除/篡改数据造成业务中断与数据完整性破坏。

## PoC

```bash
# 未授权读取员工列表（原文实测返回 288 条）
curl "http://127.0.0.1:9999/info/emp"

# 未授权新增员工（原文实测插入成功）
curl -X POST "http://localhost:9999/info/emp" \
  -H "Content-Type: application/json" \
  -d "{\"e_name\": \"李四\", \"e_sex\": 2, \"e_birth\": \"1992-05-15\", \"d_id\": 1}"
```

## 变体与关联

- 与“从鉴权配置枚举匿名路径”的源码审计方法卡属同一发现路径：先定位 `anonUrls`/`excludePaths` 等匿名配置，再与 Controller 映射对照；本卡是其一个可直接复现的完整案例。
- 与泛微 E10 `/sapi/bs/**` permitAll 通配白名单导致未授权建管理员类似，都是“通配符白名单覆盖业务路由”；差异是本例进入的是员工/部门 CRUD，危害为 PII 泄露与数据篡改，而非直接接管后台。
- 文章还审计了 JWT：服务端用“用户密码”作为 HMAC256 密钥签发/校验 token；知道密码即可伪造，但知道密码本身已能直接登录，未形成额外危害，故不单列场景。
- 头像上传接口把文件名固定为用户 ID，无法控制文件名/后缀，文章未找到可解析 JSP 的依赖，未形成可利用上传链，不单列场景。

## 检测与防御

- **收紧匿名配置**：`anonUrls` 只保留确需匿名的精确路径（如 `/security/login`），禁止用 `/info/**` 这类模块级通配符；将公共接口与业务 Controller 分到不同前缀和不同过滤器链。
- **控制器二次鉴权**：在敏感 Controller/方法上加 `@PreAuthorize`、角色注解或统一拦截器，不能只依赖前置 filter 的路径判断。
- **最小数据暴露**：员工列表接口按需返回字段，出生日期、部门等 PII 对未授权/低权用户脱敏；写操作单独授权。
- **检测**：对匿名路径集合做配置基线审计；监控未登录访问 `/info/emp`、`/info/dep` 及批量分页拉取、异常 POST/PUT/DELETE；结合访问日志发现同一 IP 遍历组织架构的行为。
- **应急**：若已暴露，评估员工 PII 泄露范围并按合规要求通报；恢复被篡改数据，轮换可能随员工信息泄露的账号资料。
