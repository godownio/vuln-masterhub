# Go Web

## 这层是什么

Go Web 框架、模板、反序列化与依赖漏洞。

## 允许放入

- 一个具体场景/技巧的蒸馏卡片（原理、触发条件、利用步骤、PoC、检测与防御）
- 该层技术的总览、术语、前置知识、目录导航
- 经过核对的攻防思路与最小复现片段

## 不允许放入

- CVE 详情与版本清单（统一放 cve/）
- 安全资讯、招聘、活动、纯新闻
- 未提炼的原文转载、长段摘录
- 与主题无关的工具安装教程

## 子目录

- （暂无子目录；新增场景卡直接放在本目录）

## 场景索引

<!-- AUTO-INDEX:START -->
| 卡片 | 状态 | 置信度 | 更新时间 |
|---|---|---|---|
| [1Panel /files/save 任意文件写入：path/content 全可控，写 /root/.ssh/authorized_keys 换 SSH 登录（CVE-2023-39966）](web-golang-1panel-files-save-arbitrary-file-write-authorized-keys.md) | verified | high | 2026-11-11 |
| [1Panel files 接口未校验 path：/download/bypath 与 /loadfile 任意文件下载/读取（CVE-2023-39965 / CVE-2023-39964）](web-golang-1panel-files-path-arbitrary-read-download.md) | verified | high | 2026-11-11 |
| [1Panel hosts/firewall/ip 命令注入：address/port 拼进 firewall-cmd 单引号命令，登录用户可执行系统命令（CVE-2023-37477）](web-golang-1panel-firewall-ip-command-injection-cve-2023-37477.md) | verified | high | 2026-11-11 |
| [Gin 中间件校验失败只 return 未 c.Abort()：IP 白名单形同虚设，未授权触达命令拼接接口 RCE](web-golang-gin-middleware-missing-abort-authz-bypass-rce.md) | verified | high | 2026-11-11 |
| [Gitea 已认证账户 RCE：任意账号在低于 1.27.1 的版本执行命令（CVE-2026-60004）](web-golang-gitea-authenticated-rce-cve-2026-60004.md) | verified | low | 2026-11-05 |
| [Go 1.22+ ServeMux 编码斜杠 %2F 双视图解析导致路径穿越读取](web-golang-servemux-encoded-slash-path-traversal.md) | verified | high | 2026-11-04 |
| [Go filepath.Join/Clean 目录遍历误区：.. 在相对 base 下保留、绝对 base 下仍可逃出基目录](web-golang-filepath-join-clean-traversal-misconception.md) | verified | medium | 2026-11-08 |
| [Go idna 纯 ASCII Punycode 标签解码漏判绕过域名校验](web-golang-golang-idna-ascii-punycode-validation-bypass.md) | verified | high | 2026-11-04 |
| [Go net/http Handler 内存马：RCE 后动态注册隐藏路由实现无文件 WebShell](web-golang-http-handler-memshell-runtime-route.md) | verified | medium | 2026-11-05 |
| [Go os.Executable 符号链接配置劫持：Windows/macOS 从链接目录读取被篡改配置](web-golang-os-executable-symlink-config-hijack.md) | verified | medium | 2026-11-08 |
| [Go pongo2 SSTI 操控 gin.Context：FormFile+SaveUploadedFile 任意文件写，覆盖 Flask 源码借 debug 热重载 RCE](web-golang-pongo2-gin-context-saveuploadedfile-debug-reload-rce.md) | verified | high | 2026-11-13 |
| [Go text/template SSTI 调出结构体方法：{{.Curl "gopher://..."}} 打本机 PUT 接口改配置，把任意文件读成“签名”回显](web-golang-text-template-method-call-curl-gopher-ssrf-localfile.md) | verified | high | 2026-11-09 |
| [Go text/template 注入 funcMap 暴露 exec：B64Decode 包裹命令绕过输入过滤执行](web-golang-go-template-funcmap-exec-b64decode-rce.md) | verified | medium | 2026-11-07 |
| [Go text/template 注入利用 echo.Context 方法链读文件：Filesystem.Open + Read 成数字数组、Seek 跳过前缀 + Stream 直接回显](web-golang-go-template-echo-context-filesystem-read.md) | verified | high | 2026-11-11 |
| [Go 上传编译服务把 multipart 文件名拼进 javac 命令行：文件名即命令注入](web-golang-multipart-filename-javac-shell-command-injection.md) | verified | medium | 2026-11-08 |
| [Go 博客链：SQLi 读 jwt_secret 伪造 admin JWT，text/template 方法调用 Configure/Ping 命令注入](web-golang-gopherblog-sqli-jwt-template-method-rce.md) | verified | high | 2026-11-06 |
| [Go 编码视图校验与解码视图路由的授权前缀绕过](web-golang-escaped-vs-decoded-path-authz-bypass.md) | verified | high | 2026-11-04 |
| [Go 编译服务 cgo Polyglot：宏定义改写与 #include/.incbin 编译期读取任意文件](web-golang-cgo-polyglot-compile-time-file-read.md) | verified | high | 2026-11-05 |
| [Go 编译服务环境变量注入：用户可控 env 覆盖 CC，cgo 构建期以 shell 执行任意命令](web-golang-build-env-cc-injection-command-exec.md) | verified | high | 2026-11-06 |
| [Gogs UpdateRepoFile 符号链接绕过 .git 校验写入 core.sshCommand 导致 RCE（CVE-2025-64111）](web-golang-gogs-updaterepofile-symlink-git-config-rce.md) | verified | high | 2026-11-05 |
| [Gogs 仓库文件编辑/UpdateRepoFile 跟随符号链接写入 hooks/pre-receive：push 触发钩子 RCE（CVE-2024-56731 / CVE-2025-8110）](web-golang-gogs-hooks-prereceive-symlink-write-rce.md) | verified | high | 2026-11-05 |
| [Gogs 内置 SSH 服务器 env 请求参数注入：环境变量名设为 --split-string 经 env -S 执行任意命令（CVE-2024-39930）](web-golang-gogs-ssh-env-split-string-argument-injection.md) | verified | high | 2026-11-07 |
| [Gogs 符号链接任意文件删除 + Git 仓库上溯劫持：删除 .git/HEAD 触发 core.sshCommand RCE](web-golang-gogs-symlink-delete-git-head-sshcommand-rce.md) | verified | high | 2026-11-07 |
| [gorilla/sessions securecookie 空 SESSION_KEY：用空密钥自签 session-name 冒充 admin](web-golang-gorilla-sessions-empty-key-session-forgery.md) | verified | high | 2026-11-13 |
| [GORM 结构体条件零值被忽略：空 token/id 使 WHERE 条件整段丢失，查询返回首条记录](web-golang-gorm-struct-zero-value-where-drop.md) | verified | high | 2026-11-11 |
| [Nginx-UI 证书导入 /api/cert 任意文件写入：路径与内容不校验，写 authorized_keys、/etc/crontab 或覆盖 app.ini 的 StartCmd 换 RCE（CVE-2024-23827）](web-golang-nginx-ui-cert-add-arbitrary-file-write.md) | verified | high | 2026-11-12 |
| [Ollama /api/generate 用户可控 template 注入：Go text/template 读取 .System/.Messages/.Tools 并操纵提示词](web-golang-ollama-template-param-go-ssti-data-leak.md) | verified | high | 2026-11-06 |
| [Python lower() 与 Go JSON 大小写折叠差异：ſ 解锁 ops 并注入 curl -F 参数](web-golang-unicode-casefold-json-field-curl-arg-injection.md) | verified | high | 2026-11-06 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
