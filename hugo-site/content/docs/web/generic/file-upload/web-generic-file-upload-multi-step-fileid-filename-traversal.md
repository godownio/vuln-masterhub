---
id: web-generic-file-upload-multi-step-fileid-filename-traversal
title: 三段式文件上传（fileId 关联）在文件名元数据处路径穿越，跨目录写系统根目录
type: scenario
domain: web
path: web/generic/file-upload
technique: multi-step-upload-fileid-filename-traversal
tags:
- file-upload
- path-traversal
- arbitrary-file-write
- fileid
- metadata
- filename
- java
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V401
  verified_at: '2026-11-09T13:01:43+08:00'
  notes: 已对照原文核对：图11-16 三段式上传（multipart srcFile/filename=blob 内容上传、JSON name/md5/chunks/fileSize 注册返回 fileId、按 fileId 查询返回 serverPath/name）、图17 直接访问 /1.txt 页面不存在、图18-20 RCE 的 ls 与 ps -aex 定位 /home/bonc 下 run.sh 与 webapp-*.jar、图21 name 改为 ../../../../../../123.txt 获新 fileId、图22 回填 fileId 上传、图23 serverPath 回显 c81230c/../../../../../../123.txt、图24 ls / 见 123.txt，均与卡内利用步骤/PoC 一致，且卡内 serverPath 原样字段与图23 相符。路径 web/generic/file-upload 合法；frontmatter 无 sources/source/source_url/文章 ID；原文未给组件版本（匿名产品），affected_versions 已 --clear。dedup 报告 recommendation=new，top 候选均为单请求 multipart filename/customPath 穿越，本卡穿越点在 JSON name 元数据且需 fileId 串联三请求，非同一利用链。未验证点：原文端点与账号打码，PoC 端点用占位符、字段按图重建，未在本机复现。dup-scan.json（2026-11-08）早于本卡建卡，无涉及本卡的 pair。
url: /docs/web/generic/file-upload/web-generic-file-upload-multi-step-fileid-filename-traversal/
draft: false
kb_aliases:
- fileId 上传路径穿越
- 三段式上传
- 上传 name 参数穿越
- serverPath 泄露落盘位置
- 跨目录任意文件写
- 分步上传文件名穿越
---

## 一句话结论

当附件/图片上传被拆成"提交文件名元数据换 fileId → 按 fileId 上传内容 → 按 fileId 查询落盘路径"三段式接口时，真正的文件名往往存在 JSON `name` 字段而不是 multipart 的 `filename`；把它改成 `../../../../../../123.txt`，服务端用"存储子目录 + name"直接拼接出的 `serverPath` 就会变成 `<子目录>/../../../../../../123.txt`，内容被写出上传根目录（本例落到系统根目录 `/123.txt`），最后用已有 RCE 执行 `ls /` 验证。

## 原理

- 分步上传把"文件内容"和"文件元数据"解耦：先用 `name`/`md5`/`chunks`/`fileSize` 注册一个逻辑文件并拿到 `fileId`，再按 `fileId` 上传内容分片，之后可以用 `fileId` 查询 `serverPath`、`name` 等元数据。文件名因此不再出现在 multipart `Content-Disposition`，常规只检查 multipart `filename` 的防护会漏掉。
- 服务端落盘时把"以 `fileId` 派生的存储子目录"和"原始文件名"做字符串拼接（如 `c81230c` + `/` + `../../../../../../123.txt`），未对 `name` 做 `basename`、`../` 过滤或规范化后的根目录校验。
- Unix 文件系统解析路径时逐级处理 `..`：从 `/<上传根>/<fileId前缀>` 出发，六层 `..` 足以走到 `/`，多余部分被根目录吸收，最终写到 `/123.txt`。
- 接口分三步、且用 `fileId` 关联，是黑盒测试的难点：必须先从响应里提取 `fileId`，再把它回填到内容上传与查询请求，才能让恶意文件名与内容落到同一个逻辑对象；直接用浏览器正常上传只会得到随机化的文件名和不可达路径。
- 本例目标为 jar 内嵌 Web 服务（目录下只有 `run.sh` 和 `webapp-*.jar`），即使写进 web 目录也不会解析 JSP，攻击者改用"写系统根目录"证明任意文件写能力；同样的原语若目标为传统 Web 容器，可直接落 webshell、计划任务或 `authorized_keys`。

## 触发条件

- 可访问后台/业务的上传功能（本例通过甲方提供的测试账号进入"添加连接→图片上传"）。
- 上传接口采用多步 fileId 协议（注册元数据、上传内容、查询信息分离），且 `name` 元数据由客户端控制。
- 服务端把 `name` 直接拼接到存储路径且未过滤 `../`、未做规范化后的根目录前缀校验。
- 运行进程对穿越后的目标目录有写权限；前置 WAF/网关未拦截 `../`。
- 有办法验证落盘结果（RCE 执行 `ls`、后续读取接口或写入可访问目录）。

## 利用步骤

1. 用正常文件走一次完整上传，抓取全部请求：内容上传（multipart，`filename="blob"`）、`fileId` 查询（返回 `serverPath`/`name`）、文件名注册（JSON `name`/`md5`/`chunks`/`fileSize`，响应返回 `fileId`）。
2. 用 Burp 全局搜索 `fileId`，确认三个请求之间的关联字段与调用顺序。
3. 把"文件名注册"请求里的 `name` 改为 `../../../../../../123.txt`，提交后记录新 `fileId`。
4. 把新 `fileId` 回填到内容上传请求（query/表单中的 `fileId`、`chunk`）和查询请求，上传内容（如 `123`）。
5. 查看查询响应：`serverPath` 形如 `c81230c/../../../../../../123.txt`，`name` 原样回显，说明穿越未被过滤、内容已按该路径落盘。
6. 通过已有 RCE（本例为 Shiro 反序列化）执行 `ls /`，确认 `/123.txt` 出现；若要进一步利用，先用 `ps -aex`、`ls /home/<user>` 定位 Web 目录/启动脚本，再把 name 换成目标文件名。

## PoC

接口路径与字段在原文中打码，以下按原文三请求结构最小化（端点以占位符表示）：

```http
# ① 注册文件名（穿越点），返回 fileId
POST /<register-endpoint> HTTP/1.1
Host: target
Content-Type: application/json

{"name":"../../../../../../123.txt","md5":"<md5>","chunks":1,"fileSize":3}

# 响应
{"msg":"success","code":1000,"data":{"fileId":"<fileId>"}}
```

```http
# ② 按 fileId 上传内容
POST /<content-endpoint>?fileId=<fileId>&chunk=0 HTTP/1.1
Host: target
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary...

------WebKitFormBoundary...
Content-Disposition: form-data; name="srcFile"; filename="blob"
Content-Type: application/octet-stream

123
------WebKitFormBoundary...--
```

```http
# ③ 按 fileId 查询落盘位置
POST /<query-endpoint> HTTP/1.1
Host: target
Content-Type: application/json

{"fileId":"<fileId>"}

# 响应（关键字段）
{"msg":"success","code":1000,"data":{"serverPath":"c81230c/../../../../../../123.txt","name":"../../../../../../123.txt","uploadType":0}}
```

随后在 RCE 命令执行界面运行 `ls /`，根目录出现 `123.txt`，证明跨目录写入成功。

## 变体与关联

- 变体（穿越字段）：有的实现把路径放在 `name`、`fileName`、`path`、`filePath`、`fileBucket` 等元数据字段；分步上传时优先测试这些 JSON 字段，而不是 multipart `filename`。
- 变体（落点）：传统 Web 容器可写 `webapps/ROOT/*.jsp`；Linux 可写 `~/.ssh/authorized_keys`、`/etc/cron.d/`、用户启动脚本；Windows 可写启动目录（参见 Guns fileBucket 卡）。
- 变体（协议）：分片上传还可能出现 `chunk`、`chunks`、`md5`、`uploadType` 等参数，`fileId` 可能由服务端生成或客户端可预测；结合 `fileId` 枚举可读取/覆盖他人文件。
- 关联：[[web-generic-file-upload-multipart-filename-traversal-ssh-key]]、[[web-generic-file-upload-adonisjs-bodyparser-filename-traversal]]（单请求 multipart filename 穿越，本卡的穿越点在 JSON 元数据）、[[web-generic-file-upload-guns-sysfileinfo-filebucket-traversal-exe-write]]（目录参数 fileBucket 穿越 + 后缀控制）、[[web-generic-file-upload-template-relative-path-original-filename-arbitrary-write]]。
- 边界：若服务端对 `name` 取 basename、生成随机文件名、或规范化后校验仍在上传根内，本手法失效；只写普通目录时降级为任意文件写。

## 检测与防御

- 检测：注册/查询接口的 `name`、`serverPath` 出现 `../`；落盘路径在响应中原样回显穿越段；上传根目录之外出现新文件（可用文件完整性/审计监控）。
- 防御：原始文件名只入库展示，落盘名使用服务端生成的 UUID；任何路径拼接前做 `basename`、拒绝 `..` 与绝对路径，并对 `getCanonicalPath()` 校验必须以上传根目录为前缀。
- 接口设计：元数据中的 `name` 不应参与路径计算；分步上传的 `fileId` 必须绑定会话/用户，防止越权关联。
- 权限：上传进程低权限运行，上传根目录独立分区；即使穿越成功也写不到系统关键目录。
