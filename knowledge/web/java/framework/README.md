# Java 框架

## 这层是什么

Spring、Struts2、Shiro、Spring Boot 等框架漏洞。

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

- [Spring](spring/README.md) —— Spring Framework/Spring Boot 漏洞与利用。
- [Struts2](struts2/README.md) —— Struts2 OGNL 与历史漏洞。
- [Shiro](shiro/README.md) —— Shiro 反序列化、RememberMe 与密钥问题。

## 场景索引

<!-- AUTO-INDEX:START -->
| 卡片 | 状态 | 置信度 | 更新时间 |
|---|---|---|---|
| [Blade 框架动态注册 Route 内存马：反射 RouteMatcher.addRoute + register](web-java-framework-blade-route-memshell.md) | verified | high | 2026-11-05 |
| [BladeX /api/blade-log/api/list 低权限读取全量日志：params 明文泄露管理员口令与 refresh_token](web-java-framework-bladex-log-api-list-credential-leak.md) | verified | high | 2026-11-07 |
| [BladeX /api/blade-user/list 只校验登录不校验角色：低权限账号读取管理员账号与联系方式](web-java-framework-bladex-user-list-missing-role-check.md) | verified | high | 2026-11-07 |
| [BladeX 角色/日志接口参数名拼接 updatexml：MySQL XPATH 报错注入回显版本](web-java-framework-bladex-role-list-updatexml-sqli.md) | verified | medium | 2026-11-07 |
| [CVE-2026-3672 JeecgBoot /sys/api/getDictItems：字典 WAF 正则与黑名单不对称导致布尔盲注](web-java-framework-jeecgboot-api-dict-waf-regex-sqli.md) | verified | high | 2026-11-05 |
| [FormService 反射分发未强制 isAccessible：service 参数可匿名调用服务类任意 public 方法](web-java-framework-formservice-reflection-dispatch-unauth.md) | verified | high | 2026-11-07 |
| [GWT-RPC 隐藏服务方法可达导致未授权命令执行](web-java-framework-gwt-rpc-hidden-method-authz-rce.md) | verified | high | 2026-11-04 |
| [Java *.do 过滤器按 URL 反射调用任意 Action 方法导致未授权 SQL 注入](web-java-framework-do-filter-reflection-dispatch.md) | verified | high | 2026-11-04 |
| [JDK 21 虚拟线程默认空名导致以线程名为键的上下文串扰与跨租户越权](web-java-framework-virtual-thread-empty-name-context-crosstalk.md) | verified | medium | 2026-11-04 |
| [JeecgBoot 3.8.3 /airag/flow/debug：任意用户提交 Groovy 脚本节点导致命令执行](web-java-framework-jeecgboot-airag-flow-debug-groovy-rce.md) | verified | high | 2026-11-05 |
| [JeecgBoot getDictItems filterSql ${} 拼接：黑名单漏 #/or，布尔盲注窃取用户与口令哈希](web-java-framework-jeecgboot-dict-filter-sql-injection.md) | verified | high | 2026-11-05 |
| [JeecgBoot ≤3.4.0 验证码 Redis Key 复用导致任意用户注册](web-java-framework-jeecgboot-captcha-redis-key-reuse-register.md) | verified | high | 2026-11-05 |
| [JeecgBoot 字典接口 SQL 注入：黑名单 select%0a/current_user/innodb_table_stats 绕过与未过滤透传](web-java-framework-jeecgboot-dict-blacklist-bypass-sqli.md) | verified | high | 2026-11-05 |
| [RuoYi 4.5.0 /common/download/resource 路径穿越任意文件读取](web-java-framework-ruoyi-download-resource-path-traversal.md) | verified | high | 2026-11-05 |
| [RuoYi-Vue-Plus <=5.4.0 sendMessageWithAttachment 任意文件读取：filePath 可控附件经邮件外带](web-java-framework-ruoyi-vue-plus-sendmessagewithattachment-arbitrary-file-read.md) | draft | high | 2026-11-07 |
| [Solon 框架 Filter 内存马：静态块反射 Context.current 链路取 ChainManager 并 addFilter 执行 cmd](web-java-framework-solon-filter-memshell-chainmanager-reflect.md) | verified | high | 2026-11-07 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
