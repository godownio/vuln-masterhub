---
title: Node.js Web
weight: 1
---

# Node.js Web

## 这层是什么

原型链污染、反序列化、模板注入与依赖漏洞。

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

- [原型链污染](prototype-pollution/) —— 原型链污染的形成、利用与 RCE 链。
- [Node.js 反序列化](deserialization/) —— node-serialize、serialize-javascript 等。
- [Node.js 模板注入](ssti/) —— EJS、Pug、Handlebars 等模板注入。

## 场景索引

<!-- AUTO-INDEX:START -->
| 卡片 | 状态 | 置信度 | 更新时间 |
|---|---|---|---|
| [ChanCMS ≤3.3.2 采集接口 new Function 代码注入：parseData 直接作为函数体执行](web-nodejs-chancms-gather-new-function-code-injection/) | verified | high | 2026-11-05 |
| [Dokploy v0.26.6 certificates.create：certificatePath 路径穿越以 root 写 chain.crt](web-nodejs-dokploy-certificate-path-traversal-file-write/) | verified | high | 2026-11-05 |
| [Dokploy v0.26.6 Compose appName 存储型命令注入：TAB 绕过 cleanAppName，stop 时 docker stack rm 执行](web-nodejs-dokploy-compose-appname-stored-command-injection/) | verified | high | 2026-11-05 |
| [Dokploy v0.26.6 destination.testConnection：accessKey 闭合双引号注入 rclone 命令执行](web-nodejs-dokploy-destination-testconnection-rclone-command-injection/) | verified | high | 2026-11-05 |
| [JS 表达式黑名单绕过：字符串拼接 constructor 取 globalThis，读 process.env 密钥](web-nodejs-expression-blacklist-string-concat-process-env/) | verified | high | 2026-11-06 |
| [jsPDF Node.js nodeReadFile 任意文件读取：loadFile/addImage/html/addFont 路径直入 fs（CVE-2025-68428）](web-nodejs-jspdf-node-readfile-arbitrary-file-read/) | verified | high | 2026-11-05 |
| [MongoDB 嵌套对象注入：可控 JSON 的 $regex 进入 findOne 做前缀盲注](web-nodejs-mongodb-json-operator-injection-prefix-oracle/) | verified | high | 2026-11-06 |
| [n8n 1.116 tournament 表达式沙箱逃逸：this 绑定全局 + 属性黑名单不全导致 process.mainModule RCE](web-nodejs-n8n-tournament-expression-this-global-mainmodule-rce/) | verified | high | 2026-11-06 |
| [n8n CVE-2026-1470 表达式沙箱逃逸：with(function(){}) 作用域 + 局部 constructor 变量绕过 AST 黑名单](web-nodejs-n8n-with-scope-constructor-ast-bypass-cve-2026-1470/) | verified | high | 2026-11-06 |
| [n8n encryptionKey 派生 JWT 密钥：读配置与数据库后伪造 admin 会话](web-nodejs-n8n-encryptionkey-jwt-forgery-admin-takeover/) | verified | high | 2026-11-05 |
| [n8n Form 端点 Content-Type 混淆：JSON 体控制 filepath 实现无认证任意文件读取（CVE-2026-21858）](web-nodejs-n8n-form-content-type-confusion-file-read/) | verified | high | 2026-11-05 |
| [n8n Git 节点 addConfig 注入 core.hooksPath：克隆非裸仓库后 commit 触发恶意 Hook RCE（CVE-2025-65964）](web-nodejs-n8n-git-node-addconfig-hookspath-rce/) | verified | high | 2026-11-06 |
| [n8n Git 节点 Clone 任意文件写入：repositoryPath 未校验导致覆盖敏感目录并 RCE（CVE-2026-21877）](web-nodejs-n8n-git-clone-arbitrary-file-write-rce/) | verified | high | 2026-11-06 |
| [n8n Git 节点裸仓库 Hook 执行：克隆数据被识别为可执行 Hook 导致认证用户 RCE（CVE-2025-62726）](web-nodejs-n8n-git-node-bare-repo-hook-rce/) | verified | medium | 2026-11-06 |
| [n8n Git 节点读取被篡改 .git/config：core.sshCommand 注入导致认证用户 RCE（CVE-2026-27498）](web-nodejs-n8n-git-node-gitconfig-sshcommand-rce/) | verified | medium | 2026-11-06 |
| [n8n Pyodide Python Code 节点沙箱逃逸：js.XMLHttpRequest.constructor 取宿主 Function 读文件/execSync RCE（CVE-2025-68668）](web-nodejs-n8n-pyodide-xmlhttprequest-constructor-host-function-escape/) | verified | high | 2026-11-06 |
| [n8n Pyodide Python Code 节点：遍历 globals() 找未封锁 constructor.constructor 的 JS 代理（items）逃逸（CVE-2025-68668 变体）](web-nodejs-n8n-pyodide-globals-constructor-enumeration/) | verified | high | 2026-11-06 |
| [n8n Python Code 节点仅封 os.system：ctypes.CDLL(None).system 直接调用 libc 绕过（CVE-2025-68668 另一路径）](web-nodejs-n8n-python-ctypes-cdll-system-sandbox-bypass/) | verified | medium | 2026-11-06 |
| [n8n Python 任务运行器 AST 黑名单漏掉 obj：e.obj 取回未过滤 builtins，字符串格式化绕过 __import__ 检测 RCE（CVE-2026-0863）](web-nodejs-n8n-python-task-runner-eobj-sandbox-escape-rce/) | verified | high | 2026-11-06 |
| [n8n 后台 Execute Command 节点：登录后建工作流直接执行系统命令](web-nodejs-n8n-authenticated-execute-command-workflow-rce/) | verified | high | 2026-11-05 |
| [n8n 表达式字段 vm2 沙箱逃逸：process.mainModule.require 执行系统命令（CVE-2025-68613）](web-nodejs-n8n-expression-sandbox-escape-rce/) | verified | high | 2026-11-05 |
| [n8n 表达式沙箱补丁绕过：对象解构计算属性键欺骗 AST，原型链取 Function 构造器执行任意 JS（CVE-2026-25049 变体）](web-nodejs-n8n-object-destructuring-computed-key-ast-bypass/) | verified | high | 2026-11-06 |
| [n8n 表达式解构赋值沙箱逃逸：CVE-2026-25049 从工作流创建到 child_process RCE](web-nodejs-n8n-expression-destructuring-constructor-rce-cve-2026-25049/) | verified | high | 2026-11-06 |
| [Next.js 中间件认证绕过（CVE-2025-29927）：伪造 x-middleware-subrequest 路径链跳过 middleware 访问 /admin](web-nodejs-nextjs-middleware-subrequest-auth-bypass-cve-2025-29927/) | verified | high | 2026-11-07 |
| [NocoBase 未授权 RCE 链：gateway 路径穿越读 JWT 密钥 + public-forms 伪造 Token 绕过认证/ACL + workflow new Function 执行](web-nodejs-nocobase-public-forms-path-traversal-jwt-workflow-rce/) | verified | low | 2026-11-05 |
| [Node-RED 编辑器未授权访问：inject + exec 节点执行系统命令（CNVD-2018-19316）](web-nodejs-node-red-unauth-editor-inject-exec-rce/) | verified | high | 2026-11-07 |
| [Node.js eval 接入字符白名单：允许 JSFuck 字符集即等于任意代码执行](web-nodejs-eval-jsfuck-char-whitelist-rce/) | verified | high | 2026-11-05 |
| [Node.js HTTP Server.prototype.emit 劫持 + Accept 头路由 + AES 通道内存马/文件马](web-nodejs-http-server-emit-hijack-header-aes-memshell/) | verified | medium | 2026-11-06 |
| [Node.js 递归 merge 过滤 __proto__ 仍可 mass assignment：/changepassword 注入 isAdmin 提权并链到 vm2 逃逸](web-nodejs-merge-proto-filter-mass-assignment-isadmin/) | verified | high | 2026-11-06 |
| [Node.js/Express 内存马：劫持 server._events.request 植入 HTTP 命令通道](web-nodejs-express-request-listener-memshell/) | verified | high | 2026-11-05 |
| [OpenCode <1.1.10 url 参数加载会话 → Markdown HTML XSS → 本地 pty API 任意命令执行（CVE-2026-22813）](web-nodejs-opencode-ai-url-param-xss-local-pty-rce/) | verified | high | 2026-11-06 |
| [OpenCode Web 无认证 shell 接口 + 宽松 CORS：任意网页跨域请求本地 4096 执行命令（CVE-2026-22812）](ai-security-agent-security-opencode-web-unauth-shell-cors-rce-cve-2026-22812/) | verified | high | 2026-11-06 |
| [opencode-ai 1.2.16 /experimental/worktree：startCommand 进 bash -lc 的盲 RCE](web-nodejs-opencode-ai-worktree-startcommand-bash-rce/) | verified | high | 2026-11-06 |
| [opencode-ai 1.2.16 /file/find：pattern 经 args.join 后进 ${{ raw }} 触发 shell 注入](web-nodejs-opencode-ai-file-find-raw-shell-injection/) | verified | high | 2026-11-06 |
| [Orval MSW 生成器路径注入：OpenAPI 路径单引号未转义导致生成代码 RCE](web-nodejs-orval-msw-route-path-code-injection/) | verified | medium | 2026-11-06 |
| [PostCSS 8.5.12–8.5.22 残余面：合法 .map 读取与 sourcesContent 源码泄露](web-nodejs-postcss-previous-sourcemap-ingestion/) | verified | high | 2026-11-05 |
| [PostCSS sourceMappingURL 注释任意文件读取与异常前缀泄露（CVE-2026-45623）](web-nodejs-postcss-sourcemappingurl-arbitrary-file-read/) | verified | high | 2026-11-05 |
| [React Native CLI Metro /open-url 端点命令注入 RCE（CVE-2025-11953）](web-nodejs-react-native-metro-open-url-command-injection/) | verified | medium | 2026-11-05 |
| [React Router @react-router/node createFileSessionStorage 未配置 secrets：会话 id 篡改经 getFile 路径穿越任意文件写入（CVE-2025-61686）](web-nodejs-react-router-file-session-id-traversal-write/) | verified | high | 2026-11-05 |
| [Strapi 密码重置 NoSQL 注入：code 传 {"$gt":0} 重置管理员密码并获取 JWT](web-nodejs-strapi-password-reset-nosql-injection/) | verified | high | 2026-11-05 |
| [Strapi 管理员插件安装命令注入：execa 拼接 plugin 参数导致 RCE（CVE-2019-19609）](web-nodejs-strapi-plugin-install-command-injection/) | verified | high | 2026-11-05 |
| [Vite 开发模式源码泄露：/src 直读 + /@fs 读服务器源码，硬编码 JWT secret 与 flag](web-nodejs-vite-dev-server-source-leak-fs/) | verified | high | 2026-11-06 |
| [vm2 沙箱内 Buffer slab 未初始化内存泄漏：布尔 oracle 逐位提取 JWT secret](web-nodejs-vm2-buffer-slab-jwt-secret-leak/) | verified | high | 2026-11-06 |
| [YApi v1.10.2 未授权 RCE：匿名注册 + project.copy 脚本注入 + 原生 vm 沙箱逃逸](web-nodejs-yapi-project-copy-script-vm-unauth-rce/) | verified | high | 2026-11-05 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
