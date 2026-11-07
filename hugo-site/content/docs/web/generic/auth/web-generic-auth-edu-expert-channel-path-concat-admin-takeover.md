---
id: web-generic-auth-edu-expert-channel-path-concat-admin-takeover
title: 教学系统多入口路径拼接越权：专家通道会话访问账号管理，添加管理员并重置 admin 密码
type: scenario
domain: web
path: web/generic/auth
technique: multi-entry-path-concat-admin-takeover
tags:
- web
- auth
- broken-access-control
- privilege-escalation
- path-bypass
- education
- account-takeover
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V213
  verified_at: '2026-11-07T04:39:05+08:00'
  notes: 已对照原文案例三与 img/22、24、26、27、30、32、34、35、38、40、42、44、46 核对：专家通道入口、-1 改 1、/admin/xxxxx.html 路径拼接、userType=1 添加管理员（Msg/Data=1）、编辑 admin 密码、下载模板 id 改 ../web.config 均与截图一致；原文未展示用户列表泄露与添加响应全字段，卡已按截图表述，保留。
url: /docs/web/generic/auth/web-generic-auth-edu-expert-channel-path-concat-admin-takeover/
draft: false
kb_aliases:
- 专家通道越权
- 账号管理路径拼接
- userType=1 添加管理员
- 教学系统管理员接管
- 多入口权限不一致
---

## 一句话结论

教学系统提供学生/教师/管理员/专家等多个登录入口，但各入口与后端接口的权限校验不一致：低权限的“专家通道”会话把已发现的 `/admin/xxxxx.html` 管理路径拼接到当前 URL 后即可访问账号管理，添加账号时客户端可控的 `userType=1` 直接创建管理员，编辑功能又允许无校验重置现有 `admin` 密码，最终完成管理员接管。

## 原理

- **多入口权限不一致**：系统为不同角色提供不同登录入口，前端按入口展示功能，但后端账号管理接口只校验“会话有效”，没有校验当前角色是否为管理员；入口处的权限判断不能替代接口级授权。
- **路径拼接绕过**：管理功能页面位于 `/admin/xxxxx.html` 一类路径下，正常入口有角色拦截；但把该路径拼接到专家通道会话的 base URL 后，请求落在同一后端控制器，页面/接口按会话放行，形成“隐藏路径 + 弱鉴权”的越权。
- **客户端可控角色字段**：添加账号请求体 `par` 为 JSON，`instructions[].userType` 由客户端提交；`userType=1` 对应管理员，服务端未将可选角色限制在当前用户权限范围内，普通会话即可创建管理员。
- **密码编辑缺少校验**：账号列表的“编辑”功能允许直接修改任意账号（包括 `admin`）的密码，未要求当前密码、未校验操作者角色，也未要求管理员二次确认；拿到编辑接口即可重置管理员密码。
- **为什么能串成链**：专家通道提供低权限会话 → 路径拼接进入账号管理 → 添加管理员获得新管理员 → 编辑 admin 密码获得原管理员 → 完整后台权限，后续可继续发现文件下载等管理员功能。

## 触发条件

- 目标教学系统存在多个登录入口（学生/教师/管理员/专家等），且不同入口的会话可访问共享后端。
- 管理功能路径可被发现（URL 参数变化、错误页、前端 JS、历史记录等）。
- 账号管理页面/接口按会话放行，未做角色/对象级授权。
- 添加账号接口接受客户端提交的 `userType`，编辑接口允许修改任意账号密码。
- 攻击者拥有一个低权限账号（专家通道/学生/教师均可）。

## 利用步骤

1. 从登录页识别“专家通道”等非管理员入口，注册/获取一个低权限账号并登录。
2. 观察 URL 中的数字参数（文章示例把 `-1` 改为 `1` 可让页面进入某些后台状态），并通过错误页、跳转、前端 JS/历史记录收集管理路径，如 `/admin/xxxxx.html`。
3. 在专家通道会话下，把管理路径拼接到当前 base URL 后访问；若页面返回账号管理列表而非登录页/403，确认路径拼接越权。
4. 抓取“添加账号”请求，修改 `par` JSON 中 `userType` 为 `1`（管理员），提交新账号；响应 `{"Msg":1,"Data":"1"}` 表示创建成功。
5. 用新管理员账号登录（或先确认其权限），再对账号列表中 `admin` 行使用“编辑”，把密码改为攻击者掌握的值；该操作无当前密码/角色校验。
6. 用 `admin` 新密码登录，获得完整管理员权限；继续测试大数据管理/模板导出等功能。

## PoC

添加管理员请求模板（字段来自文章截图，值已打码；`par` 前可能有随机前缀/签名，需按抓包保留）：

```http
POST /<admin-path>/<account-endpoint> HTTP/1.1
Host: target.edu.cn
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-Requested-With: XMLHttpRequest
Cookie: <expert-channel-session>

par={"instructions":[{"instructId":-201,"oP":"","userId":"","userName":"attacker","userPwd":"Passw0rd!","userType":"1","userArea":"","userSchool":"","refIp":0,"sign":"<sign>"}]}
```

响应：

```json
{"Msg":1,"Data":"1"}
```

重置管理员密码：在账号管理列表对 `admin` 行发起编辑请求，提交新的 `userPwd` 即可（文章截图显示编辑弹窗可直接修改 `admin` 密码，无额外校验）。

## 变体与关联

- **角色值变体**：`userType` 可能为 `1`=管理员、`2`=指导老师、`3`=学生等；先用低权限账号确认枚举，再尝试高权限值。
- **路径变体**：管理页面可能在 `/admin/`、`/manage/`、`/system/` 下；可尝试把已发现路径与不同入口的 base URL 组合，或对路径做大小写/编码/后缀绕过。
- **批量添加**：若存在“批量添加/导入”接口，可一次创建多个管理员，减少请求次数。
- **关联**：[[web-generic-auth-403-resource-suffix-path-dictionary-bypass]]（路径后缀绕过 403）、[[web-generic-auth-deepaudit-user-list-missing-role-check-pii-leak]]（用户列表缺角色校验）、[[web-generic-auth-authenticated-change-password-idor]]（登录后改密越权）。

## 检测与防御

- **接口级授权**：账号管理、添加、编辑、删除等接口必须在服务端校验当前用户角色与目标对象权限，不能只依赖入口页面/前端菜单。
- **禁止客户端决定角色**：`userType` 由服务端根据授权范围映射，普通会话只能创建其权限允许的角色；管理角色创建需管理员审批/二次认证。
- **改密校验**：修改他人密码需管理员权限 + 当前密码/二次确认；管理员账号改密应强制重新认证并告警。
- **路径不可作为安全边界**：不要依赖“隐藏管理路径”；所有 `/admin/*` 路由统一走管理员鉴权中间件。
- **检测**：同一低权限会话访问 `/admin/*`、创建 `userType=1` 账号、修改 `admin` 密码、以及异常登录入口切换；对这些行为做审计与实时告警。
