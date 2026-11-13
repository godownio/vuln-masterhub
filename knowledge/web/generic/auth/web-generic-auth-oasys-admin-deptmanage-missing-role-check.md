---
id: web-generic-auth-oasys-admin-deptmanage-missing-role-check
title: OASYS 后台管理控制器缺少角色校验：普通用户会话直接访问 /deptmanage 等部门管理页面（垂直越权）
type: scenario
domain: web
path: web/generic/auth
technique: oasys-admin-controller-missing-role-check-vertical-privilege
aliases:
- OASYS 越权
- 部门管理未鉴权
- deptmanage 垂直越权
- 后台菜单隐藏不等于鉴权
- SpringBoot OA 管理接口缺少权限设置
tags:
- web
- java
- springboot
- oasys
- access-control
- vertical-privilege-escalation
- missing-authz
- code-audit
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V552
  verified_at: '2026-11-11T22:59:45+08:00'
  notes: 已对照原文与26张截图核对：普通用户wuianan会话(JSESSIONID=44D8...)GET /deptmanage返回200并展示总经办/研发部/财务部/市场部/人事部及修改/人事调动/删除按钮（img23/25），deptmanage控制器仅接收Model、直接deptdao.findAll()无userId/角色判断（img26）；修正卡中'deptmanage依赖@SessionAttribute(userId)'的不准确表述为：deptmanage连userId都不取，其它接口普遍用@SessionAttribute但同样不校验角色。原文其余半条链（fastjson 1.2.36未调用JSON.parseObject、两处${}SQL注入仅报错未打通、jsp上传可传但UUID随机不可控路径、Long型fileid/pathid穿越失败、XSS未展开）均与截图一致，已按跳过处理。原文称审计历史版本、未给版本号，affected_versions保持省略正确。dedup候选为CookieShop/xxl-job/BladeX/开放签等其它产品缺失授权实例，非同链。未验证点：未在本机复现越权请求。
---

## 一句话结论

OASYS（cn.gson.oasys，SpringBoot 1.5.6 + MyBatis）的后台管理控制器没有做任何角色/权限判断：`/deptmanage` 的方法体只接收 `Model`、直接 `deptdao.findAll()` 查全表并渲染，连当前用户都不取；其它接口普遍只用 `@SessionAttribute("userId")` 取当前登录用户，同样不校验角色。普通用户登录后控制台虽然不显示"用户管理/部门管理"等菜单，但用同一会话 Cookie 直接请求 `GET /deptmanage` 即可打开部门管理页并读取全部部门数据；原文进一步称管理员的操作接口都未做权限设置。

## 原理

- **前端隐藏不是鉴权**：后台侧边栏按角色只渲染部分菜单（普通用户看不到用户管理/部门管理），但菜单只是前端展示逻辑；后端 `@RequestMapping` 路由是否可达完全取决于服务器端有没有拦截器/过滤器/注解校验。
- **控制器代码**：`@RequestMapping("deptmanage") public String deptmanage(Model model) { List<Dept> depts = deptdao.findAll(); model.addAttribute("depts", depts); return "user/deptmanage"; }`——方法体没有任何 `userId`/角色判断，直接查全表并渲染。
- **会话即可通过**：`deptmanage` 控制器连 `userId` 都不取，直接查全表渲染；其它管理/业务接口普遍用 `@SessionAttribute("userId")` 只取当前登录用户、不校验角色（任何登录用户都有 userId），所以低权限账号的 Cookie 与管理员一样能进入；原文用普通用户 Cookie 重放管理员页面请求，响应正常返回部门列表。
- **为什么有效**：Spring MVC 路由不区分调用者角色，管理接口与普通接口共用同一套 Controller；开发者把"管理员才能看到菜单"误当成"管理员才能访问接口"，形成典型垂直越权（missing function-level access control）。
- **影响**：可读取管理员页面数据（部门/用户/角色等），若对应的增删改接口同样无校验，则低权限用户可修改或删除管理员数据；原文称"管理员的操作接口都未作权限设置"，但只对部门管理页的读取做了实测。

## 触发条件

- 目标为 OASYS 相应历史版本（原文审计的是历史版本，最新版未审计）；后台控制器未接入统一的权限拦截（如 Spring Security 或自定义 HandlerInterceptor 校验角色）。
- 攻击者拥有任意可登录的低权限账号（普通用户即可），且会话 Cookie 有效。
- 管理页面路由可从浏览记录/源码/菜单 URL 推断（如 `/deptmanage`、`/usermanage` 等）。
- 目标未对后台 URL 做来源/IP 限制。

## 利用步骤

1. 用普通账号登录 OASYS，获取会话 Cookie（如 `JSESSIONID`、`inindexedulogin_sys_user_` 等）。
2. 观察管理员界面或无权限用户的菜单差异，确定被隐藏的管理路由（如 `/deptmanage`）。
3. 用普通用户的 Cookie 直接请求该路由：
   ```http
   GET /deptmanage HTTP/1.1
   Host: 127.0.0.1:8088
   Cookie: JSESSIONID=<普通用户会话>; ...
   ```
4. 响应返回部门管理页面与部门列表（原文实测 200，页面含总经办/研发部/财务部/市场部/人事部等数据）。
5. 继续枚举其它管理路由（用户列表、角色/权限、系统设置等），并按页面按钮对应的接口尝试写操作（原文未逐一验证）。

## PoC

原文实测请求（普通用户会话）：

```http
GET /deptmanage HTTP/1.1
Host: 127.0.0.1:8088
Cookie: inindexedulogin_sys_user_=inindexedulogin_sys_user_1;
        inindexedweb_user_login=a67a6ad7c56348b787a5423d8dbacb77;
        JSESSIONID=44D8FEBD031E8E0BFB7463E6E6395E3D
Referer: http://127.0.0.1:8088/index
```

响应：200，部门管理页面，包含部门名称/电话/邮箱/地址与"修改/人事调动/删除"等操作入口。

对应控制器：

```java
@RequestMapping("deptmanage")
public String deptmanage(Model model) {
    List<Dept> depts = deptdao.findAll();
    model.addAttribute("depts", depts);
    return "user/deptmanage";
}
```

## 变体与关联

- **同类垂直越权卡**：库内 BladeX `/api/blade-user/list` 只校验登录不校验角色、CookieShop 后台订单删除接口缺失鉴权、IceCMS `ChangeUser` 水平越权等，均为"后端缺授权判断"的不同产品实例；本卡补充 OASYS 后台管理控制器。
- **越权形态**：水平越权（同角色改他人数据，靠可控 userId）、垂直越权（低权限调高权限接口，靠可控路由）；本案为纯路由级垂直越权，不依赖 ID 篡改。
- **测试变体**：直接重放管理员请求、改 Cookie 角色字段、访问未在菜单暴露的 URL、枚举 Spring 控制器路径（如 `/user/*`、`/role/*`）；也可结合 Swagger/actuator 暴露的映射表发现接口。
- **与文件上传/文件读取的关系**：同一系统还存在扩展名不校验的上传与 Long 型 fileid 文件接口（原文尝试越权/穿越均未成功），说明审计时"有漏洞点"与"可利用"需分开评估。

## 检测与防御

- **服务端授权**：在拦截器/过滤器或 Spring Security 中对所有 `/admin/**`、管理控制器统一校验角色（如 `ADMIN`），不要依赖菜单隐藏；按方法加 `@PreAuthorize` 或自定义权限注解。
- **审计方法**：遍历所有 `@RequestMapping` 控制器，检查方法体内是否有角色/权限判断；用低权限账号对管理路由做批量重放测试。
- **检测**：低权限会话访问管理 URL（`/deptmanage` 等）出现在访问日志；同一会话在短时间内枚举多个管理路由；响应状态 200 且页面含管理数据。
- **加固**：后台与管理接口分离部署/来源限制（VPN、IP 白名单）；对敏感操作加二次确认与审计日志。

## 备注

- 原文为 OASYS 历史版本审计记录：fastjson 1.2.36 存在但代码未调用 `JSON.parseObject`；两处 MyBatis `${}` 拼接的 SQL 注入（outaddresspaging baseKey、sortMyNotice baseKey）仅观察到 SQL 报错/未打通；上传 .jsp 后缀不校验但文件名随机生成、无法控路径；文件读取/删除因参数为 Long 未成功；XSS 全站无过滤但未展开。以上均按未打通/半条链跳过，仅越权场景成卡。
- 越权实测仅覆盖 `/deptmanage` 页面读取；"所有管理员操作接口均无权限设置"为原文表述，未逐一验证，故 confidence 标 medium。
