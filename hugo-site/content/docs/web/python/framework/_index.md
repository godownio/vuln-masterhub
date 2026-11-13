---
title: Python 框架
weight: 1
---

# Python 框架

## 这层是什么

Flask、Django、FastAPI 等框架漏洞。

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
| [aiohttp 静态路由 follow_symlinks=True 分支 joinpath(filename).resolve() 未校验子路径：`..` 穿越读取任意文件（XVE-2024-1472，3.9.2 修复）](web-python-framework-aiohttp-add-static-follow-symlinks-path-traversal/) | verified | high | 2026-11-11 |
| [AstrBot CVE-2025-48957：auth_middleware 放行 /api/chat/get_file + os.path.join 路径遍历任意文件读取](web-python-framework-astrbot-cve-2025-48957-get-file-auth-bypass-path-traversal/) | verified | high | 2026-11-06 |
| [AstrBot 硬编码 JWT 密钥 + 插件上传 RCE（CVE-2025-55449）：伪造 HS256 token 调用 /api/plugin/install-upload 触发 __import__ 执行](web-python-framework-astrbot-cve-2025-55449-hardcoded-jwt-plugin-upload-rce/) | verified | high | 2026-11-06 |
| [authentik LDAP Source debug 接口 filter_backends 置空导致匿名越权读取目录元数据（CVE-2026-55106）](web-python-framework-authentik-ldap-debug-filter-backends-bypass/) | verified | high | 2026-11-05 |
| [D-Tale 硬编码 SECRET_KEY 伪造 Flask 会话 + settings.query 落盘，经 run_query 的 df.query 执行代码（CVE-2024-3408）](web-python-framework-dtale-hardcoded-secret-session-settings-query-rce/) | verified | high | 2026-11-09 |
| [Django DEBUG 错误页泄露 settings：JENKINS_AUTHORIZATION Basic 凭据与 JENKINS_URL 被读出](web-python-framework-django-debug-settings-jenkins-basic-credential-leak/) | verified | medium | 2026-11-07 |
| [Django SQL Explorer 后台 SQL 执行：SELECT load_extension 加载上传 DLL 到 RCE](web-python-django-sql-explorer-load-extension-dll-rce/) | verified | high | 2026-11-06 |
| [Django 关系查询盲注 + Nginx ..%2f 路径穿越：从密码哈希到管理后台](web-python-framework-django-orm-relationship-blind-injection-nginx-path-bypass/) | verified | high | 2026-11-06 |
| [FastAPI + Jinja2 SSTI 无回显：request.__class__.__init__.__globals__ 取 sys/eval，app.add_api_route 注入内存马](web-python-framework-fastapi-jinja2-ssti-add-api-route-memshell/) | verified | high | 2026-11-07 |
| [FastAPI 路由注册内存马：遍历 sys.modules 定位 FastAPI 实例并动态注册后门路由](web-python-framework-fastapi-sys-modules-route-memshell/) | verified | high | 2026-11-06 |
| [FastAPI/ASGI 中间件 __call__ 热补丁内存马：gc.get_objects() 定位实例，工厂模式应用也能注入](web-python-framework-fastapi-gc-asgi-middleware-memshell/) | verified | high | 2026-11-06 |
| [Flask error_handler_spec 404 错误处理器内存马：RC4 加密命令通道 + X-Token-Auth 鉴权](web-python-framework-flask-error-handler-404-rc4-backdoor/) | verified | high | 2026-11-06 |
| [Flask teardown 钩子内存马：teardown_request/teardown_appcontext 响应后执行与静态目录落盘回显](web-python-framework-flask-teardown-hook-memshell/) | verified | high | 2026-11-09 |
| [Flask 会话签名密钥弱口令爆破与 Cookie 伪造：flask-unsign --unsign/--sign 冒充任意用户并枚举有效用户名](web-python-framework-flask-session-weak-secret-bruteforce-forge-enum/) | verified | high | 2026-11-12 |
| [Flask 启动时模板清单快照 + 可控崩溃重启：写入恶意 Jinja 模板后绕过白名单触发 SSTI](web-python-framework-flask-template-list-startup-snapshot-restart-ssti/) | verified | high | 2026-11-08 |
| [Flask 头像 URL 下载全链：file:// 任意读 → Redis CRLF 提权 → RestrictedUnpickler → root XML-RPC 读 flag](web-python-framework-flask-avatar-url-file-read-redis-crlf-pickle-root-rpc/) | verified | high | 2026-11-06 |
| [Flask 方法覆盖与组件注册型内存马：handle_user_exception/process_response/jinja_env](web-python-framework-flask-method-override-component-memshell/) | verified | high | 2026-11-05 |
| [Flask 调试模式 Werkzeug 控制台 PIN 可预测伪造导致任意代码执行](web-python-framework-flask-werkzeug-debug-pin-forgery/) | verified | high | 2026-11-05 |
| [Flask 运行期改写 static_folder 指向根目录：经 /static/ 读取任意文件](web-python-framework-flask-static-folder-arbitrary-file-read/) | verified | medium | 2026-11-05 |
| [Flask 钩子注册表内存马：SSTI/eval 直接改写 before/after/url_value/template_context 钩子](web-python-framework-flask-hook-registry-memshell/) | verified | high | 2026-11-05 |
| [Flask 高版本路由注册内存马：重置 _got_first_request 绕过 @setupmethod 动态加路由](web-python-framework-flask-route-registration-memshell/) | verified | high | 2026-11-05 |
| [h3blog /admin/download 无鉴权路径穿越：fileName 逃逸 uploads 任意文件读取并在下载后删除](web-python-framework-h3blog-download-path-traversal-file-read-delete/) | verified | high | 2026-11-07 |
| [h3blog 后台代码生成字段注入：把元数据写进生成的 Python 视图源码，访问生成接口触发 os.system RCE](web-python-framework-h3blog-gencode-field-code-injection-rce/) | verified | high | 2026-11-07 |
| [httpx multipart boundary 注入 + Werkzeug 临时文件 /proc/self/fd 竞争：从 API_KEY 泄露到 Jinja SSTI RCE](web-python-framework-httpx-boundary-injection-werkzeug-tempfile-jinja-ssti/) | verified | medium | 2026-11-06 |
| [JSON 里的 \u005f 绕过 dunder 黑名单：污染 Flask app.config 的 XML 串，再用本地路径实体读文件](web-python-framework-json-unicode-dunder-blacklist-bypass-config-xml-xxe/) | verified | medium | 2026-11-09 |
| [JumpServer 作业 Playbook 关键字黑名单绕过：\u 转义 delegate_to/ansible_connection 骗过文本检查，Ansible local 连接在 Celery 容器执行命令（CVE-2024-29201）](web-python-framework-jumpserver-playbook-unicode-keyword-bypass-local-rce/) | verified | high | 2026-11-10 |
| [MaxKB <1.9.0 函数库 debug 接口代码执行（CVE-2024-56137）：code 落盘 py 后经 subprocess 执行](web-python-framework-maxkb-cve-2024-56137-function-lib-debug-rce/) | verified | high | 2026-11-08 |
| [Mercury 未授权 Jupyter Kernel API 导致 RCE](web-python-framework-mercury-unauth-jupyter-kernel-rce/) | verified | high | 2026-11-04 |
| [Mercury 路径黑名单漏逗号导致 /lab 与终端接口未授权](web-python-framework-mercury-blocklist-comma-terminal/) | verified | high | 2026-11-04 |
| [MindsDB CVE-2025-68472：PUT /api/files JSON 上传分支跳过校验，os.path.join 路径遍历未授权任意文件读取](web-python-framework-mindsdb-cve-2025-68472-file-api-json-path-traversal/) | verified | high | 2026-11-06 |
| [pgAdmin 4 ≤8.4 Windows 认证后 RCE（CVE-2024-3116）：filemanager 上传恶意 psql.exe + validate_binary_path 执行可控路径二进制](web-python-framework-pgadmin-cve-2024-3116-validate-binary-path-upload-rce/) | verified | medium | 2026-11-09 |
| [pgAdmin 4 ≤9.1 认证后 RCE（CVE-2025-2945）：借已配置 PostgreSQL 连接执行 Python](web-python-framework-pgadmin-cve-2025-2945-authenticated-rce/) | verified | medium | 2026-11-05 |
| [pydash.set_ 可控路径篡改 Flask jinja_loader.searchpath 读取任意模板文件](web-python-framework-pydash-set-jinja-loader-searchpath/) | verified | high | 2026-11-05 |
| [Pyramid 运行时路由内存马：栈帧回溯取 Configurator，add_route/add_view 后必须 commit 才生效](web-python-framework-pyramid-runtime-route-memshell-commit/) | verified | medium | 2026-11-08 |
| [Python AST 规则引擎签名规范化碰撞与 exec 剪枝缺陷导致沙箱逃逸](web-python-framework-ast-eval-signature-canonicalization-bypass/) | verified | high | 2026-11-05 |
| [PyTorch distributed RPC 任意函数调用：加入集群的 worker 通过 rpc_sync 让 master 执行 eval 等任意可调用对象](web-python-framework-pytorch-rpc-arbitrary-function-call-rce/) | verified | high | 2026-11-07 |
| [Rasa model_server 响应头 filename 路径穿越任意文件写入](web-python-framework-rasa-model-server-filename-path-traversal/) | verified | high | 2026-11-05 |
| [Rasa 恶意模型 metadata.json 图 schema 动态导入导致 RCE](web-python-framework-rasa-model-metadata-importlib-rce/) | verified | high | 2026-11-05 |
| [Rasa 未授权上传恶意模型替换对话内容](web-python-framework-rasa-malicious-model-dialogue-hijack/) | verified | medium | 2026-11-05 |
| [Sanic static handler 关键词污染：pydash.set_ 沿 __class__.__init__.__globals__ 改 directory_view/_parts/file_or_directory 实现目录遍历与任意文件读取](web-python-framework-sanic-static-handler-keywords-pollution/) | verified | high | 2026-11-08 |
| [任意文件读取泄露硬编码 WERKZEUG_DEBUG_PIN：Flask 调试控制台直接 RCE](web-python-framework-flask-debug-pin-file-read-console-rce/) | verified | high | 2026-11-05 |
| [共享 Jupyter Server Contents API 无租户作用域：同实例同根目录下的跨隔离文件状态信道](web-python-framework-jupyter-contents-shared-root-state-channel/) | verified | medium | 2026-11-05 |
| [旧版 Werkzeug 调试控制台 /console 无 PIN 保护：直接执行 Python 表达式 RCE](web-python-framework-werkzeug-legacy-console-no-pin-rce/) | verified | high | 2026-11-09 |
| [覆盖 wsgiref.simple_server.WSGIServer.application 完成整应用替换：不落盘、不影响后续请求解析的 WSGI 层内存马（原路由表被整体顶替）](web-python-framework-wsgiref-server-application-overwrite-memshell/) | verified | medium | 2026-11-09 |
| [调试反馈接口按 trace_id 回显序列化堆栈：hex 编码 pickle 对象内嵌 flag](web-python-framework-debug-feedback-trace-pickle-leak/) | verified | high | 2026-11-06 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
