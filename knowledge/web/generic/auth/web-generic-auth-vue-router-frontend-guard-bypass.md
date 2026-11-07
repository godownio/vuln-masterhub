---
id: web-generic-auth-vue-router-frontend-guard-bypass
title: Vue SPA 仅在前端校验路由守卫导致隐藏管理页面暴露
type: scenario
domain: web
path: web/generic/auth
technique: vue-router-frontend-guard-bypass
aliases:
- Vue 路由守卫绕过
- 前端鉴权绕过
- VueCrack 清守卫
- SPA 隐藏路由暴露
- 前端 token 伪造
tags:
- vue
- spa
- vue-router
- auth-bypass
- frontend
- unauthorized
- route-guard
- recon
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-04'
updated: '2026-11-05'
verification:
  verified_by: verifier-V9
  verified_at: '2026-11-05T00:32:55+08:00'
  notes: 已对照原文与图06/08/11核对：VueCrack 枚举完整路由并清除路由守卫后，可直接访问 /#/administration 管理页；创建用户并登录后获得后台功能。卡内已明确页面可达不等于接口鉴权，定位为发现原语并与未授权用户创建卡衔接，severity=medium 合理。原文未涉及版本区间。未在本机执行任何请求。
---

## 一句话结论

当 Vue Router 只在 `beforeEach` 中检查 `localStorage` 是否存在 token 来决定是否放行路由时，攻击者可伪造 token 或清空路由守卫，直接进入隐藏的管理页面并枚举其后端接口；页面本身不是安全边界，真正的危害取决于对应 API 是否也缺少服务端鉴权。

## 原理

- Vue/React 等 SPA 会把所有路由与页面代码打包进前端 bundle。路由守卫（`router.beforeEach`）运行在浏览器里，用户可以修改、Hook 或直接绕过它。
- 常见错误实现是：`if (!localStorage.getItem('token')) next('/login')`。它只检查 token “存在”，不校验签名、有效期、角色，也不阻止用户手动写入一个任意字符串。
- 路由的 `meta.auth`/`requiresAuth` 等标记同样在前端代码里，攻击者可以在运行时修改路由表、清空守卫或直接访问目标 URL（hash 模式 `#/admin` 或 history 模式 `/admin`）。
- 专门插件（如 VueCrack、AntiDebug Breaker 的 Vue 面板）可以枚举完整路由、清除路由守卫和跳转，帮助发现正常导航中看不到的管理页面。
- 绕过守卫只解决“页面能否渲染”。如果后端 API 仍校验会话，页面会显示“请先登录/获取列表失败”；只有当某个 API 也缺少鉴权时，才会转化为数据读取或写入。
- 因此该技术本身是攻击面发现原语：它暴露隐藏路由和接口路径，后续仍需逐个测试 API 的服务端鉴权。

## 触发条件

- 目标使用 Vue/React 等 SPA，路由表打包在前端。
- 路由守卫只依赖前端可改状态（localStorage/sessionStorage/内存变量/token 存在性），没有服务端强制校验。
- 管理路由或隐藏功能路由存在于 bundle 中，且后端对应接口可被直接访问。
- 攻击者能加载浏览器插件或手动执行 JS（常规 Web 访问即可）。

## 利用步骤

1. 用指纹/资产测绘定位 Vue 资产。例如按机构与 Vue 图标哈希筛选：
   `org="<目标机构>" && icon_hash=="<Vue 图标哈希>"`
2. 打开目标站点，加载 Vue 路由分析插件，开启“获取路由”“清除路由守卫”“清除跳转”。
3. 在插件中查看完整 URL 列表，寻找 `/admin`、`/administration`、`/manage` 等隐藏路由。
4. 直接访问隐藏路由；若被重定向到登录页，使用“清除跳转”或禁用守卫后再次访问。
5. 在管理页面逐个点击功能，或用插件/DevTools 的 Network 面板记录其调用的 API。
6. 对每个 API 去掉 Cookie/Token 重放，判断是否存在服务端鉴权缺失；缺失时进入具体的未授权读写场景。

## PoC

```js
// 控制台伪造一个“存在”的 token（仅对只检查存在性的守卫有效）
localStorage.setItem('token', 'anything');
location.hash = '#/administration';
location.reload();
```

```text
# 使用 Vue 路由插件时的等价操作：
# 1) 获取路由 -> 列出 bundle 中的全部 path
# 2) 清除路由守卫 -> 去掉 beforeEach 的登录检查
# 3) 清除跳转 -> 阻止 302/路由重定向到 /login
# 4) 打开 /#/administration 或 /administration
```

```bash
# 页面能打开不代表接口可用：直接请求管理 API，观察是否仍要求登录
curl -i 'https://target.example/api/admin/users'
# 若返回 401/“请先登录”，说明后端仍有鉴权；
# 若返回数据或允许写入，则与未授权 API 场景组合成完整利用链。
```

## 变体与关联

- 变体：history 模式直接访问 `/admin`；hash 模式访问 `/#/admin`；路由懒加载 chunk 可在 Network 中直接看到。
- 变体：修改 `route.meta.auth`/`requiresAuth` 或替换 `router.beforeEach` 为空函数。
- 变体：从 webpack/vite 产物中提取 `apiUrlKey` 与接口清单，不依赖插件（见关联卡片）。
- 关联：[[pentest-recon-webpack-apiurlkey-endpoint-extraction]]（从 SPA 产物提取隐藏 API）；[[web-generic-auth-unauth-user-create-admin-takeover]]（守卫绕过暴露页面后，利用未授权创建用户接口接管后台）；[[web-generic-auth-jwt-signature-only-role-bypass]]（服务端只校验签名不校验角色的另一类垂直越权）。
- 边界：如果后端对每个 API 都做会话与角色校验，绕过守卫只能看到空页面/报错，不能读取或修改数据；此时应把它当作信息暴露而非未授权访问。

## 检测与防御

- 检测：监控对管理路由对应 API 的无会话请求；关注同一 IP 在短时间内枚举大量前端路由/接口；前端错误日志中出现大量 401 但页面仍被访问。
- 修复：所有后端接口必须独立做认证与授权，不能依赖前端守卫；管理接口按角色做服务端校验；不要把敏感路由/功能仅靠前端隐藏。
- 加固：token 使用服务端可验证的签名并校验过期/角色；管理端使用独立域名与强会话；对前端 bundle 做敏感信息清理；CSP 降低 XSS 辅助风险。
