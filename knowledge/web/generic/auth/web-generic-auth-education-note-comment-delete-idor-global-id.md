---
id: web-generic-auth-education-note-comment-delete-idor-global-id
title: 在线教育平台笔记/评论删除接口只凭全站自增 id：不校验资源归属，改 id 即可水平越权删除他人内容并遍历清空
type: scenario
domain: web
path: web/generic/auth
technique: education-ugc-delete-idor-global-incremental-id
aliases:
- 删除接口越权
- 笔记删除 IDOR
- 评论删除越权
- 全站自增 id 遍历删除
- BOLA 删除
tags:
- web
- idor
- bola
- horizontal-privilege-escalation
- missing-ownership-check
- education
- ugc
- delete
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V551
  verified_at: '2026-11-11T22:48:56+08:00'
  notes: 已通读 content.md 并逐张核对全部 9 张截图：图1 教育平台首页（登录/注册入口）、图2 个人中心侧栏含收藏/点赞/评论/笔记等功能、图3 视频页记笔记面板、图4 创建笔记请求 {"note":"<p>阿卡我是哈哈</p>","resourceId":133,"videoId":914} 返回 code 0/status 200/timestamp、图5 删除笔记请求 {"id":47,"note":...,"resourceId":133,"videoId":914} 返回 status 200、图6 B 账号发表评论、图7 评论列表响应 records[0].id=46/commentContent=一个评论/insertBy 等、图8 A 的 Cookie+Jwt-Token 对 /jy-application-resmgr/resmgr-comment/deleteComment 发送 [46] 返回 status 200/timestamp 1705757102496、图9 B 的评论列表共 0 条（越权删除成功）。卡内 PoC 的请求体、响应体（含 timestamp）与截图一致；仅占位内容 <p>test</p> 为示意替换。dedup：仅自身 exact；同根因候选 newbeemall cart delete、zentao file delete、order comment idor 等均为不同产品/业务对象/入口与 PoC，属同型不同链，按 dedup_review 保留本卡。原文未标注软件版本，未设 affected_versions。未验证点：未复测目标站点（文章为真实 EduSRC 中危案例，双账号实测截图已证明最终危害）；创建笔记完整 URL 与删除笔记接口名在截图中被截断，PoC 中 resmgr-note/deleteNote 为按同类命名推断。
---

## 一句话结论

在线教育平台的“记笔记/评论”删除接口只接收一个全站自增的资源 id 并凭请求者本人的 JWT 执行删除，后端不校验该 id 是否属于当前用户；攻击者登录自己的账号，改 id 为他人笔记/评论的 id（可从个人中心列表或发包观察得到）即可删除他人内容，向 0 遍历即可清空全站 UGC。

## 原理

- **对象级授权缺失（BOLA/IDOR）**：JWT/Cookie 只证明“请求者是谁”，删除操作还需要证明“该对象属于请求者”。后端把客户端提交的 `id` 直接当作删除条件（如 `DELETE FROM note WHERE id=?`），没有附加 `AND user_id=<session user>`，于是任何已登录用户都能操作任意 id 的对象。
- **id 可预测且会泄露**：笔记/评论 id 由后端按全站计数自增分配（与用户无关），创建笔记时响应/后续请求可见 `resourceId`/`videoId`/`id`，个人中心“我的评论/笔记”列表接口也会返回 id（示例评论 id=46）。id 连续可枚举，遍历即可覆盖其他用户的数据。
- **删除参数里的冗余字段不参与校验**：笔记删除请求还携带了 `note`、`resourceId`、`videoId`，但后端只用 `id` 定位并执行删除，其余字段可原样复制或伪造，进一步说明没有归属校验。
- **危害**：属于水平越权/数据完整性破坏——可批量删除他人评论、笔记、点赞、收藏等 UGC，影响平台内容与用户数据（示例提交 EduSRC 评为中危）；如果同一模式出现在“删除账号/订单/文件”等接口，危害会更高。

## 触发条件

- 攻击者拥有一个可正常登录的账号（普通用户即可）。
- 目标存在按 id 操作个人资源的接口（删除笔记/评论/收藏/点赞等），且只校验登录态、不校验对象归属。
- 资源 id 为连续自增或可在列表/响应中获取；接口无频率限制或限制宽松。
- 服务端没有对批量/异常删除做审计告警。

## 利用步骤

1. 注册/登录账号 A，在视频页创建一条笔记，抓创建请求（JSON：`note`、`resourceId`、`videoId`），观察响应与后续列表中的 id 分配规律。
2. 在个人中心删除自己的笔记/评论，抓删除请求，确认参数：笔记删除带 `id`、`note`、`resourceId`、`videoId`，评论删除带 `id`（可能为数组）；确认请求仅依赖本人 JWT。
3. 注册账号 B，发表一条评论，在 B 的个人中心/接口响应中获取该评论 id（示例为 46）。
4. 回到 A 的删除请求，把 id 改为 B 的评论 id 重放；响应 `status:200`/`code:0` 说明删除成功。
5. 登录 B 确认内容消失；将 id 从当前值向下遍历（0..N）可批量删除全站同类型内容（注意授权与测试边界，仅限授权靶场/众测范围）。

## PoC

创建笔记（获取 id 分配规律）：

```http
POST /jy-application-resmgr/resmgr-note/... HTTP/1.1
Host: <target>
Cookie: <A 的会话>
Content-Type: application/json

{"note":"<p>test</p>","resourceId":133,"videoId":914}
```

删除笔记（A 的请求，id 可改为他人笔记）：

```http
POST /jy-application-resmgr/resmgr-note/deleteNote HTTP/1.1
Host: <target>
Cookie: <A 的会话>
Content-Type: application/json

{"id":47,"note":"<p>test</p>","resourceId":133,"videoId":914}
```

删除评论（A 的 JWT + B 的评论 id=46）：

```http
POST /jy-application-resmgr/resmgr-comment/deleteComment HTTP/1.1
Host: <target>
Cookie: <A 的会话>
Jwt-Token: <A 的 JWT>
Content-Type: application/json

[46]
```

响应：

```json
{"code":"0","data":null,"message":null,"status":200,"timestamp":1705757102496}
```

随后 B 账号个人中心的评论列表为 0 条。

## 变体与关联

- 变体：同一平台的“点赞/收藏/观看记录/笔记”删除或修改接口通常共用同一套“只凭 id”的逻辑，可一并测试；修改类（改他人评论内容）与读取类（查看他人私密笔记）也可能是同源缺陷。
- 变体：id 若为 UUID 不可枚举，仍可通过分享链接、列表接口、导出功能泄露后越权删除。
- 关联：[[web-generic-auth-zentao-file-delete-idor]]（删除接口缺对象权限校验的同型案例）、[[web-generic-auth-order-comment-idor-missing-ownership]]（按 orderId 操作他人订单评价）、[[web-generic-auth-idor-current-path-replacement-sibling-crud]]（IDOR 接口面扩展与兄弟 CRUD 接口发现）。
- 边界：需要有效登录态；若服务端在删除前做了 `select ... where id=? and user_id=?` 或使用归属校验中间件则不受影响；仅删除自己内容不属于漏洞。

## 检测与防御

- 修复：所有对象级操作在 SQL/ORM 层强制附加归属条件（`WHERE id=? AND owner_id=<session user>`），或先查对象再比对 owner；管理端删除单独鉴权。
- 标识：资源 id 使用不可枚举的 UUID/雪花 id，降低遍历可行性（但不能替代归属校验）。
- 审计与限流：对删除类接口按用户/IP 限流，记录操作者、对象 id、对象 owner，异常批量删除告警。
- 测试建议：注册双账号交叉验证读/改/删接口，重点检查只带 id 的 POST/DELETE 请求与列表接口返回的 id 字段。
