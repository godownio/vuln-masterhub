---
id: web-java-component-hugegraph-authenticationfilter-getpath-semicolon-whitelist-bypass
title: HugeGraph AuthenticationFilter 鉴权绕过：getUriInfo().getPath() 未归一化 + endsWith 白名单，任意路径追加 ;versions 即跳过认证（CVE-2024-27349）
type: scenario
domain: web
path: web/java/component
technique: hugegraph-authenticationfilter-getpath-semicolon-endsWith-bypass
aliases:
- CVE-2024-27349
- HugeGraph 鉴权绕过
- isWhiteAPI
- endsWith 白名单
- 分号矩阵参数绕过
- WHITE_API_LIST
tags:
- java
- hugegraph
- jersey
- auth-bypass
- path-parsing
- matrix-parameter
- semicolon
- cve
cve:
- CVE-2024-27349
severity: high
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V411
  verified_at: '2026-11-09T14:54:32+08:00'
  notes: 已对照原文与截图核对：isWhiteAPI 用 context.getUriInfo().getPath() 与 WHITE_API_LIST=[auth/login,versions] 做 path.endsWith（图19 path=graphs/hugegraph/auth/users;versions、whiteApi=versions、endsWith 命中）；curl /graphs/hugegraph/auth/users;versions 未认证返回 admin/test 用户（含 bcrypt 密码哈希、邮箱、创建者，图18）；原文明确 gremlin 仍受二层 AUTHORIZATION 拦截。未验证点：PoC 未复跑；原文未给该 CVE 明确版本区间，不设 affected_versions。提示：变体中的 ;versions/ 带有结尾斜杠，按同一 endsWith("versions") 逻辑不会命中，建议作者删除或改为 ;%76ersions 等可解码为 versions 的形式。
---

## 一句话结论

HugeGraph 开启认证后，`AuthenticationFilter.isWhiteAPI` 用 `context.getUriInfo().getPath()` 取未归一化的相对路径，并对白名单 `["auth/login","versions"]` 做 `path.endsWith(whiteApi)` 判断；攻击者在任意受保护 API 路径后追加 `;versions`（如 `/graphs/hugegraph/auth/users;versions`），`endsWith("versions")` 为真使过滤器放行，而 Jersey 路由会剥离 `;` 后的矩阵参数、仍匹配原 controller，从而未认证读取用户列表等接口（CVE-2024-27349）。

## 原理

- **过滤器逻辑**：`AuthenticationFilter#filter` 先调 `isWhiteAPI(context)`；`isWhiteAPI` 取 `context.getUriInfo().getPath()`，遍历 `WHITE_API_LIST = ["auth/login","versions"]`，只要 `path.endsWith(whiteApi)` 就返回 true，跳过后续认证。
- **getPath 的语义**：JAX-RS `UriInfo.getPath()` 返回相对应用上下文的解码后路径（无前导 `/`），且**保留 `;` 矩阵参数**、不做归一化；`/graphs/hugegraph/auth/users;versions` 得到 `graphs/hugegraph/auth/users;versions`，以 `versions` 结尾。
- **路由的语义**：Jersey 在匹配资源时忽略路径段中 `;` 之后的矩阵参数，因此该请求仍路由到 `/graphs/hugegraph/auth/users` 对应的 controller。
- **鉴权与路由语义不一致**：过滤器按“字符串后缀”认为这是白名单接口，路由按“矩阵参数剥离后的段”认为这是用户管理接口，二者认知错位造成未授权访问。
- **影响范围（原文验证）**：`curl http://target:8080/graphs/hugegraph/auth/users;versions` 返回用户列表（含用户名、邮箱、bcrypt 密码哈希、创建者等）；调试图显示 `path="graphs/hugegraph/auth/users;versions"`、`whiteApi="versions"`、endsWith 命中。
- **边界**：该绕过不能直接打通 Gremlin 执行——构造 Gremlin 请求后 HugeGraph 还会向 gremlin-server 发新请求，那里有第二层 AUTHORIZATION 鉴权；但其他 API 可正常绕过，可先取用户信息再寻找后续利用。

## 触发条件

- HugeGraph 开启认证（`StandardAuthenticator` + `WsAndHttpBasicAuthHandler` + `HugeFactoryAuthProxy`）。
- 受影响版本（原文未给出该 CVE 的明确版本区间，按公告核对）。
- 攻击者能发送带 `;` 矩阵参数的 HTTP 请求，前置网关/WAF 未拦截或未重写 `;`。
- 目标 API 路径不需要在过滤器内做其他二次校验。

## 利用步骤

1. 确认目标开启认证：不带凭据访问 `/graphs/<graph>/auth/users` 返回 401。
2. 在路径后追加 `;versions` 发送同一请求，观察是否返回 200 及业务数据。
3. 用调试图/日志确认 `isWhiteAPI` 的 path 与 whiteApi 匹配（`endsWith("versions")`）。
4. 遍历其他受保护 API（用户、schema、task 等）套用同一后缀，收集信息。
5. 将获得的用户/配置信息用于后续攻击（如借其他 API 或凭据尝试 Gremlin）；注意 gremlin-server 侧还有第二层鉴权。

## PoC

```http
GET /graphs/hugegraph/auth/users;versions HTTP/1.1
Host: <target>:8080

# 等价 curl
curl "http://<target>:8080/graphs/hugegraph/auth/users;versions"
```

```text
# 返回示例（节选）
[{"user_name":"admin","user_email":"123@xx.com","user_password":"$2a$04$..."},
 {"user_name":"test","user_phone":"13000000000",...}]
```

## 变体与关联

- 变体：`;auth/login`、`;versions/`、`;%76ersions` 等编码/多分号形式；其他以 `endsWith`/`contains` 匹配白名单的 JAX-RS 过滤器同样可用分号矩阵参数绕过。
- 关联：与 [[web-generic-auth-jersey-getpath-isbasefile-semicolon-dot-jwt-bypass]] 同属 Jersey `getPath()` 保留矩阵参数导致的鉴权/路由语义差异，但那张的放行逻辑是 `isBaseFile`（含点即文件），本卡是 `endsWith` 白名单；与 [[web-generic-auth-hanvon-eface-whitelist-contains-semicolon-path-bypass]]（contains + `..;/`）同族不同实现。
- 与 CVE-2024-27347（Hubble SSRF 到 Gremlin）组合：先用鉴权绕过取信息、再由 Hubble SSRF 执行 Gremlin，是同一产品的两条链。

## 检测与防御

- 检测：请求路径包含 `;`、`%3b` 并以 `versions`/`auth/login` 结尾却命中其他 controller；过滤器白名单命中与路由结果不一致；无凭据却返回 200 的受保护 API。
- 防御：升级到 1.3.0+；鉴权前剥离矩阵参数、URL 解码、归一化 `..` 并统一前导斜杠，再与白名单做**精确匹配**；不要在 `getPath()` 结果上做 endsWith/contains 启发式；网关拦截异常 `;` 路径；对敏感 API 增加资源级二次鉴权。
