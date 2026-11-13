# Python Web

## 这层是什么

Python 反序列化、SSTI、框架与依赖漏洞。

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

- [Python 反序列化](deserialization/README.md) —— pickle、PyYAML、jsonpickle 等反序列化风险。
- [Python SSTI](ssti/README.md) —— Jinja2、Mako、Tornado 模板注入。
- [Python 框架](framework/README.md) —— Flask、Django、FastAPI 等框架漏洞。

## 场景索引

<!-- AUTO-INDEX:START -->
| 卡片 | 状态 | 置信度 | 更新时间 |
|---|---|---|---|
| [Base64 解码服务解析差异：Python b64decode 在 `=` 处截断绕过白名单，shell base64 拼接后执行命令](web-python-base64-padding-parser-differential-command-injection.md) | verified | high | 2026-11-07 |
| [ComfyUI-Impact-Pack /upload/temp 文件名目录穿越任意写：写 custom_nodes/git/__init__.py 或 ComfyUI-Manager 启动脚本实现 RCE（CVE-2024-21575）](web-python-comfyui-impact-pack-upload-filename-traversal-startup-rce.md) | verified | high | 2026-11-07 |
| [ComfyUI-Manager /manager/get_openart_auth 等接口未授权读写第三方凭据：明文返回 OpenArt/Matrix/YouML 密钥](web-python-comfyui-manager-unauth-thirdparty-credential-endpoints.md) | verified | high | 2026-11-06 |
| [ComfyUI-Manager 3.37 security_level=weak 放行高权限接口：上传 config.ini + git_url 克隆恶意节点 + reboot 触发 RCE（CVE-2025-67303）](web-python-comfyui-manager-weak-config-git-clone-reboot-rce.md) | verified | high | 2026-11-05 |
| [ComfyUI-Manager CRLF 注入 security_level=weak + reboot + git_url 安装恶意节点：克隆仓库的 install.py 在安装阶段执行 RCE](web-python-comfyui-manager-crlf-security-level-weaken-install-py-rce.md) | verified | high | 2026-11-06 |
| [ComfyUI-Manager CVE-2026-22777：ConfigParser CRLF 注入 git_exe 配置劫持 GitPython 触发 RCE](web-python-comfyui-manager-cve-2026-22777-configparser-crlf-git-exe-rce.md) | verified | high | 2026-11-06 |
| [ComfyUI-Manager QVD-2026-2759：/snapshot/restore 路径穿越 + userdata 写入恶意快照，重启恢复时安装远程仓库执行 install.py](web-python-comfyui-manager-snapshot-restore-path-traversal-qvd-2026-2759.md) | verified | medium | 2026-11-06 |
| [Django 登录接口对 base64 参数 eval 导致未授权 RCE（chkid/chkport）](web-python-django-login-eval-base64-user-input-rce.md) | verified | high | 2026-11-05 |
| [Flask config 对象污染：merge 写入 config.filename 导致任意文件读取](web-python-flask-config-object-pollution-filename-file-read.md) | verified | medium | 2026-11-06 |
| [js2py CVE-2024-28397 沙盒逃逸：Object.getOwnPropertyNames 泄露 PyObjectWrapper，沿 __subclasses__ 找到 subprocess.Popen 执行命令](web-python-js2py-cve-2024-28397-pyobjectwrapper-subclasses-popen-escape.md) | verified | high | 2026-11-08 |
| [JSON Unicode 转义绕过前置 WAF：检查原文、json.loads 后还原敏感字符串](web-python-waf-json-unicode-escape-bypass.md) | verified | high | 2026-11-05 |
| [pydash.set_ 反斜杠转义绕过「_.」过滤：__class__\\.__init__ 既避开字符串检查又按点分割进入 dunder 链](web-python-pydash-set-backslash-dot-path-escape-bypass.md) | verified | high | 2026-11-09 |
| [pydash.set_ 路径穿越导致 Python 类属性、模块全局与 Flask/Jinja 配置污染](web-python-pydash-set-attribute-path-pollution.md) | verified | high | 2026-11-05 |
| [Python merge 污染模块全局 __file__：源码回显路由变任意文件读取](web-python-merge-globals-file-source-echo-arbitrary-read.md) | verified | medium | 2026-11-08 |
| [Python 代码执行 WAF 绕过：关键字拆分与动态属性构造](web-python-waf-bypass-dynamic-attribute-keyword-split.md) | verified | high | 2026-11-05 |
| [Python 代码执行 WAF 绕过：编码与 Unicode 归一化](web-python-waf-bypass-encoding-unicode-normalization.md) | verified | high | 2026-11-05 |
| [Python 属性污染改 os.path.pardir：绕过 Jinja split_template_path 的 .. 检查读取模板目录外文件](web-python-attribute-pollution-ospath-pardir-jinja-traversal-bypass.md) | verified | medium | 2026-11-13 |
| [Python 标识符 NFKC 归一化：方法名折叠覆盖与兼容字符压缩长度](web-python-unicode-normalization-identifier-collision-length.md) | verified | high | 2026-11-05 |
| [Python 沙箱任意文件写逃逸：向 site-packages 写 .pth/sitecustomize.py，宿主解释器启动前自动执行](web-python-sandbox-site-packages-pth-sitecustomize-escape.md) | verified | high | 2026-11-06 |
| [Python 类属性污染：__class__.__base__ 注入 execute_method 经 eval 执行](web-python-class-pollution-execute-method-eval.md) | verified | medium | 2026-11-06 |
| [Python 运行时函数劫持：用 types.CodeType 替换 __code__](web-python-codetype-function-code-hijack.md) | verified | high | 2026-11-05 |
| [Python 递归 merge 属性污染：config.filename 改为 /flag 后任意文件读取](web-python-recursive-merge-config-filename-arbitrary-read.md) | verified | high | 2026-11-06 |
| [Python 递归合并类污染：__class__.__base__ 改类属性与 __init__.__globals__ 篡改全局（提权/SECRET_KEY/RCE）](web-python-recursive-merge-class-pollution-globals-rce.md) | verified | high | 2026-11-05 |
| [Searchor 2.4.0 eval 注入：engine/query 拼进 eval 的 search() 调用，闭合单引号后加 __import__('os').system() 即可未授权 RCE（2.4.2 修复）](web-python-searchor-eval-engine-query-import-os-system-rce.md) | verified | high | 2026-11-13 |
| [上传目录穿越写 .pth 到 site-packages：任意 Python 启动即执行](web-python-upload-traversal-pth-sitepackages-rce.md) | verified | high | 2026-11-06 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
