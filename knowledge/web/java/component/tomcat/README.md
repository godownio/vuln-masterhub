# Tomcat

## 这层是什么

Tomcat 漏洞、Session 与文件处理。

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
| [jshERP v3.6 补丁绕过：原始 URI 前缀白名单 + Tomcat 分号路径参数归一化差异，未授权建管理员后 pf4j 插件 RCE](web-java-component-jsherp-filter-prefix-normalization-plugin-rce.md) | verified | high | 2026-11-05 |
| [Tomcat 9.0.97 CVE-2024-50379 大小写文件系统条件竞争：上传 JSP 被当脚本编译 getshell](web-java-component-tomcat-cve-2024-50379-case-race-rce.md) | verified | high | 2026-11-05 |
| [Tomcat Adapter 内存马：替换 AbstractProcessor.adapter 的 CoyoteAdapter](web-java-component-tomcat-adapter-memshell.md) | verified | high | 2026-11-05 |
| [Tomcat CVE-2017-12615：PUT 方法 + `/1.jsp/` 后缀绕过写入 JSP WebShell](web-java-component-tomcat-cve-2017-12615-put-jsp-upload.md) | verified | high | 2026-11-05 |
| [Tomcat CVE-2025-24813：部分 PUT 写入 .session 临时文件 + JSESSIONID 触发 PersistentManager 反序列化 RCE](web-java-component-tomcat-cve-2025-24813-partial-put-session-deserialization-rce.md) | verified | high | 2026-11-07 |
| [Tomcat Digester 运行时 JSP webshell：自定义规则 + base64 XML 触发 setter JNDI](web-java-component-tomcat-digester-jsp-runtime-webshell.md) | verified | high | 2026-11-05 |
| [Tomcat Executor 内存马：替换 NioEndpoint 线程池解析原始请求](web-java-component-tomcat-executor-memshell.md) | verified | high | 2026-11-05 |
| [Tomcat Listener 内存马：StandardContext.addApplicationEventListener 注入请求监听器](web-java-component-tomcat-listener-memshell.md) | verified | high | 2026-11-05 |
| [Tomcat multipart 未完成请求保持临时文件 fd 打开](web-java-component-tomcat-multipart-tempfile-fd.md) | verified | medium | 2026-11-04 |
| [Tomcat RFC2231 文件名高位截断：filename*=UTF-8''sh.陪sp 绕过扩展名黑名单落盘 JSP](web-java-component-tomcat-rfc2231-filename-char-truncation-jsp-upload.md) | verified | high | 2026-11-05 |
| [Tomcat Servlet 内存马：反射 StandardContext 创建 Wrapper 并注册 ServletMapping](web-java-component-tomcat-standardcontext-servlet-memshell.md) | verified | high | 2026-11-05 |
| [Tomcat Tribes EncryptInterceptor 解密失败仍转发导致未授权反序列化 RCE（CVE-2026-34486）](web-java-component-tomcat-tribes-encryptinterceptor-deserialization-rce.md) | verified | high | 2026-11-05 |
| [Tomcat Upgrade 内存马：向 httpUpgradeProtocols 注册恶意 UpgradeProtocol](web-java-component-tomcat-upgrade-memshell.md) | verified | high | 2026-11-05 |
| [Tomcat Valve 内存马：StandardContext Pipeline 注入恶意 Valve](web-java-component-tomcat-valve-memshell.md) | verified | high | 2026-11-05 |
| [Tomcat XML 配置经 Digester 自动调用 setter 触发 JNDI 注入](web-java-component-tomcat-xml-digester-setter-jndi.md) | verified | high | 2026-11-05 |
| [Tomcat 动态注册 Filter 内存马：StandardContext.addFilterDef/addFilterMapBefore/filterStart](web-java-component-tomcat-dynamic-filter-memshell.md) | verified | high | 2026-11-05 |
| [哥斯拉 FilterShell：Tomcat 动态 Filter 内存马（Cookie 触发 + noLog）](web-java-component-tomcat-godzilla-filtershell-memshell.md) | verified | high | 2026-11-05 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
