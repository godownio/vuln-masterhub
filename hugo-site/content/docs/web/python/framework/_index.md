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
| [AstrBot CVE-2025-48957：auth_middleware 放行 /api/chat/get_file + os.path.join 路径遍历任意文件读取](web-python-framework-astrbot-cve-2025-48957-get-file-auth-bypass-path-traversal/) | verified | high | 2026-11-06 |
| [AstrBot 硬编码 JWT 密钥 + 插件上传 RCE（CVE-2025-55449）：伪造 HS256 token 调用 /api/plugin/install-upload 触发 __import__ 执行](web-python-framework-astrbot-cve-2025-55449-hardcoded-jwt-plugin-upload-rce/) | verified | high | 2026-11-06 |
| [authentik LDAP Source debug 接口 filter_backends 置空导致匿名越权读取目录元数据（CVE-2026-55106）](web-python-framework-authentik-ldap-debug-filter-backends-bypass/) | verified | high | 2026-11-05 |
| [Django SQL Explorer 后台 SQL 执行：SELECT load_extension 加载上传 DLL 到 RCE](web-python-django-sql-explorer-load-extension-dll-rce/) | verified | high | 2026-11-06 |
| [Django 关系查询盲注 + Nginx ..%2f 路径穿越：从密码哈希到管理后台](web-python-framework-django-orm-relationship-blind-injection-nginx-path-bypass/) | verified | high | 2026-11-06 |
| [FastAPI 路由注册内存马：遍历 sys.modules 定位 FastAPI 实例并动态注册后门路由](web-python-framework-fastapi-sys-modules-route-memshell/) | verified | high | 2026-11-06 |
| [FastAPI/ASGI 中间件 __call__ 热补丁内存马：gc.get_objects() 定位实例，工厂模式应用也能注入](web-python-framework-fastapi-gc-asgi-middleware-memshell/) | verified | high | 2026-11-06 |
| [Flask error_handler_spec 404 错误处理器内存马：RC4 加密命令通道 + X-Token-Auth 鉴权](web-python-framework-flask-error-handler-404-rc4-backdoor/) | verified | high | 2026-11-06 |
| [Flask 头像 URL 下载全链：file:// 任意读 → Redis CRLF 提权 → RestrictedUnpickler → root XML-RPC 读 flag](web-python-framework-flask-avatar-url-file-read-redis-crlf-pickle-root-rpc/) | verified | high | 2026-11-06 |
| [Flask 方法覆盖与组件注册型内存马：handle_user_exception/process_response/jinja_env](web-python-framework-flask-method-override-component-memshell/) | verified | high | 2026-11-05 |
| [Flask 调试模式 Werkzeug 控制台 PIN 可预测伪造导致任意代码执行](web-python-framework-flask-werkzeug-debug-pin-forgery/) | verified | high | 2026-11-05 |
| [Flask 运行期改写 static_folder 指向根目录：经 /static/ 读取任意文件](web-python-framework-flask-static-folder-arbitrary-file-read/) | verified | medium | 2026-11-05 |
| [Flask 钩子注册表内存马：SSTI/eval 直接改写 before/after/url_value/template_context 钩子](web-python-framework-flask-hook-registry-memshell/) | verified | high | 2026-11-05 |
| [Flask 高版本路由注册内存马：重置 _got_first_request 绕过 @setupmethod 动态加路由](web-python-framework-flask-route-registration-memshell/) | verified | high | 2026-11-05 |
| [httpx multipart boundary 注入 + Werkzeug 临时文件 /proc/self/fd 竞争：从 API_KEY 泄露到 Jinja SSTI RCE](web-python-framework-httpx-boundary-injection-werkzeug-tempfile-jinja-ssti/) | verified | medium | 2026-11-06 |
| [Mercury 未授权 Jupyter Kernel API 导致 RCE](web-python-framework-mercury-unauth-jupyter-kernel-rce/) | verified | high | 2026-11-04 |
| [Mercury 路径黑名单漏逗号导致 /lab 与终端接口未授权](web-python-framework-mercury-blocklist-comma-terminal/) | verified | high | 2026-11-04 |
| [MindsDB CVE-2025-68472：PUT /api/files JSON 上传分支跳过校验，os.path.join 路径遍历未授权任意文件读取](web-python-framework-mindsdb-cve-2025-68472-file-api-json-path-traversal/) | verified | high | 2026-11-06 |
| [pgAdmin 4 ≤9.1 认证后 RCE（CVE-2025-2945）：借已配置 PostgreSQL 连接执行 Python](web-python-framework-pgadmin-cve-2025-2945-authenticated-rce/) | verified | medium | 2026-11-05 |
| [pydash.set_ 可控路径篡改 Flask jinja_loader.searchpath 读取任意模板文件](web-python-framework-pydash-set-jinja-loader-searchpath/) | verified | high | 2026-11-05 |
| [Python AST 规则引擎签名规范化碰撞与 exec 剪枝缺陷导致沙箱逃逸](web-python-framework-ast-eval-signature-canonicalization-bypass/) | verified | high | 2026-11-05 |
| [Rasa model_server 响应头 filename 路径穿越任意文件写入](web-python-framework-rasa-model-server-filename-path-traversal/) | verified | high | 2026-11-05 |
| [Rasa 恶意模型 metadata.json 图 schema 动态导入导致 RCE](web-python-framework-rasa-model-metadata-importlib-rce/) | verified | high | 2026-11-05 |
| [Rasa 未授权上传恶意模型替换对话内容](web-python-framework-rasa-malicious-model-dialogue-hijack/) | verified | medium | 2026-11-05 |
| [任意文件读取泄露硬编码 WERKZEUG_DEBUG_PIN：Flask 调试控制台直接 RCE](web-python-framework-flask-debug-pin-file-read-console-rce/) | verified | high | 2026-11-05 |
| [共享 Jupyter Server Contents API 无租户作用域：同实例同根目录下的跨隔离文件状态信道](web-python-framework-jupyter-contents-shared-root-state-channel/) | verified | medium | 2026-11-05 |
| [调试反馈接口按 trace_id 回显序列化堆栈：hex 编码 pickle 对象内嵌 flag](web-python-framework-debug-feedback-trace-pickle-leak/) | verified | high | 2026-11-06 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
