---
id: web-generic-xss-unauth-stored-xss-hot-question
title: 未授权新增热点问题接口导致后台存储型 XSS
type: scenario
domain: web
path: web/generic/xss
technique: unauth-stored-xss-content-field
tags:
- web
- xss
- stored-xss
- unauthorized
- api
- admin-panel
- content-management
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-04'
updated: '2026-11-05'
verification:
  verified_by: verifier-V9
  verified_at: '2026-11-05T00:32:59+08:00'
  notes: 已对照原文与图17/19/20核对：未授权热点问题新增接口可写入内容，标题等字段提交 <img src=x onerror=console.log(1)> 后，图20 控制台输出 1；部分字段被解析、部分未解析，卡中逐字段测试建议与边界一致。原文只验证 console.log，未证明会话窃取。原文未涉及版本区间。PoC 未在本机执行。
url: /docs/web/generic/xss/web-generic-xss-unauth-stored-xss-hot-question/
draft: false
kb_aliases:
- 未授权存储型 XSS
- 热点问题 XSS
- 前台写接口 XSS
- 后台存储型 XSS
- 缺少鉴权的富文本字段
---

## 一句话结论

当“新增热点问题/公告/内容”接口未做服务端鉴权，且标题、分类、答案等字段在后台列表或详情中原样渲染为 HTML 时，未登录攻击者可写入 `<img src=x onerror=...>` 等载荷，在管理员浏览页面时触发存储型 XSS。

## 原理

- 内容管理类接口通常把用户输入保存到数据库，后台列表/详情再拼接进 HTML 返回。若输出时没有 HTML 编码，浏览器会把输入中的标签和事件处理器当作代码执行。
- 如果“新增”接口本身没有认证/授权，攻击者无需登录即可写入内容；这比需要登录的存储型 XSS 门槛更低，也更容易批量投放。
- `<img src=x onerror=console.log(1)>` 是常用验证载荷：图片加载失败触发 `onerror`，不需要用户交互；用 `console.log` 而不是 `alert` 可以避免弹窗干扰业务、降低被发现概率。
- 不同字段的渲染方式可能不同：有的字段被富文本编辑器解析，有的被转义，有的被截断。攻击者应对标题、分类、答案内容、来源等每个可写字段分别测试。
- 存储型 XSS 在管理后台执行时，攻击者可以读取页面 DOM、以管理员身份发起操作、窃取未设置 HttpOnly 的会话 Cookie，或配合 CSRF 执行管理动作。

## 触发条件

- 存在未鉴权的内容新增接口（热点问题、公告、文章、评论、配置项等）。
- 至少一个字段在后台页面/用户页面被原样渲染为 HTML，未做输出编码或安全过滤。
- 管理员或其他高权限用户会浏览包含该内容的页面。
- 页面没有严格的 CSP 阻断内联事件处理器。

## 利用步骤

1. 通过前端路由枚举/抓包找到内容管理页面及其新增接口。
2. 去掉 Cookie/Token 重放新增请求，确认未登录也能写入。
3. 对每个可写字段分别提交验证载荷，例如 `<img src=x onerror=console.log(1)>`。
4. 保存后回到列表/详情页，打开 DevTools Console，确认载荷执行（打印 `1`）。
5. 对未执行的字段调整上下文（属性、JS 字符串、富文本）或换用其他标签/事件。
6. 验证危害后可替换为窃取会话、发起管理操作或钓鱼的载荷（需在授权范围内）。

## PoC

```http
POST /api/admin/hotQuestion/add HTTP/1.1
Host: target.example
Content-Type: application/json

{
  "title": "<img src=x onerror=console.log(1)>",
  "category": "<img src=x onerror=console.log(1)>",
  "answers": [
    {
      "content": "<img src=x onerror=console.log(1)>",
      "source": "<img src=x onerror=console.log(1)>"
    }
  ]
}
```

```text
# 保存后访问热点问题列表/详情，Console 输出：
1
```

```html
<!-- 常用最小验证载荷 -->
<img src=x onerror=console.log(1)>
```

## 变体与关联

- 变体：富文本字段可用 `<svg onload=...>`、`<details open ontoggle=...>` 等；被过滤时尝试大小写、双写、实体编码等绕过。
- 变体：如果只有部分字段解析 HTML，优先选择进入后台列表摘要的字段（标题、分类），触达管理员概率更高。
- 变体：结合未授权写入批量投放，或把载荷放在“待审核”内容中等待管理员审核时触发。
- 关联：[[web-generic-xss-filter-bypass-encoding-obfuscation]]、[[web-generic-xss-scriptless-execution-vectors]]（载荷绕过与替代载体）；[[web-generic-auth-vue-router-frontend-guard-bypass]]（发现隐藏内容管理路由）。
- 边界：案例只验证了 `console.log` 执行，未证明能窃取会话；若 Cookie 为 HttpOnly 且 CSP 严格，实际接管管理员的难度更高。不同字段的解析/转义行为差异很大，必须逐字段测试。

## 检测与防御

- 检测：审计所有内容写入接口的认证与授权；对后台页面输出做 XSS 扫描；监控包含 `<script`、`onerror=`、`onload=` 等特征的入库内容；关注未登录来源的内容创建。
- 修复：写入接口要求认证与角色校验；所有输出按上下文做 HTML/属性/JS 编码；富文本使用白名单过滤（如 OWASP AntiSamy/DOMPurify 服务端对应实现）。
- 加固：设置 `Content-Security-Policy` 限制内联脚本；会话 Cookie 设置 `HttpOnly`、`SameSite`；对管理后台增加二次确认与操作审计。
