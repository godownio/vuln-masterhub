---
title: Java 框架
weight: 1
---

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

- [Spring](spring/) —— Spring Framework/Spring Boot 漏洞与利用。
- [Struts2](struts2/) —— Struts2 OGNL 与历史漏洞。
- [Shiro](shiro/) —— Shiro 反序列化、RememberMe 与密钥问题。

## 场景索引

<!-- AUTO-INDEX:START -->
| 卡片 | 状态 | 置信度 | 更新时间 |
|---|---|---|---|
| [Blade 框架动态注册 Route 内存马：反射 RouteMatcher.addRoute + register](web-java-framework-blade-route-memshell/) | verified | high | 2026-11-05 |
| [BladeX /api/blade-log/api/list 低权限读取全量日志：params 明文泄露管理员口令与 refresh_token](web-java-framework-bladex-log-api-list-credential-leak/) | verified | high | 2026-11-07 |
| [BladeX /api/blade-user/list 只校验登录不校验角色：低权限账号读取管理员账号与联系方式](web-java-framework-bladex-user-list-missing-role-check/) | verified | high | 2026-11-07 |
| [BladeX 角色/日志接口参数名拼接 updatexml：MySQL XPATH 报错注入回显版本](web-java-framework-bladex-role-list-updatexml-sqli/) | verified | medium | 2026-11-07 |
| [CVE-2026-3672 JeecgBoot /sys/api/getDictItems：字典 WAF 正则与黑名单不对称导致布尔盲注](web-java-framework-jeecgboot-api-dict-waf-regex-sqli/) | verified | high | 2026-11-05 |
| [DWR plaincall 任意路径未授权调用：/dwr/interface/*.js 枚举方法签名后执行无参 getSMTPConfig 泄露 SMTP 凭据](web-java-framework-dwr-plaincall-interface-js-unauth-config-leak/) | verified | high | 2026-11-08 |
| [DWR 未授权方法调用触发 SQL 异常：BadSqlGrammarException/MySQLSyntaxErrorException 回显完整 SQL 语句与表列名](web-java-framework-dwr-sql-exception-full-statement-disclosure/) | verified | high | 2026-11-08 |
| [DWR 组件 debug 索引暴露：按 dwr.xml allow 列表构造 /dwr/exec 请求未授权调用服务端方法](web-java-framework-dwr-debug-index-exec-unauth-method-invoke/) | verified | high | 2026-11-08 |
| [FormService 反射分发未强制 isAccessible：service 参数可匿名调用服务类任意 public 方法](web-java-framework-formservice-reflection-dispatch-unauth/) | verified | high | 2026-11-07 |
| [GWT-RPC 隐藏服务方法可达导致未授权命令执行](web-java-framework-gwt-rpc-hidden-method-authz-rce/) | verified | high | 2026-11-04 |
| [Java *.do 过滤器按 URL 反射调用任意 Action 方法导致未授权 SQL 注入](web-java-framework-do-filter-reflection-dispatch/) | verified | high | 2026-11-04 |
| [JDK 21 虚拟线程默认空名导致以线程名为键的上下文串扰与跨租户越权](web-java-framework-virtual-thread-empty-name-context-crosstalk/) | verified | medium | 2026-11-04 |
| [JeecgBoot 3.7.2 拖拽数据集 getTotalData 的 concat 黑名单绕过：字段名改用「username,password,salt」多列裸写，渲染后仍是多列输出](web-java-framework-jeecgboot-jimureport-comma-field-concat-check-bypass/) | verified | high | 2026-11-07 |
| [JeecgBoot 3.8.3 /airag/flow/debug：任意用户提交 Groovy 脚本节点导致命令执行](web-java-framework-jeecgboot-airag-flow-debug-groovy-rce/) | verified | high | 2026-11-05 |
| [JeecgBoot getDictItems filterSql ${} 拼接：黑名单漏 #/or，布尔盲注窃取用户与口令哈希](web-java-framework-jeecgboot-dict-filter-sql-injection/) | verified | high | 2026-11-05 |
| [JeecgBoot ≤3.4.0 验证码 Redis Key 复用导致任意用户注册](web-java-framework-jeecgboot-captcha-redis-key-reuse-register/) | verified | high | 2026-11-05 |
| [JeecgBoot 字典接口 SQL 注入：黑名单 select%0a/current_user/innodb_table_stats 绕过与未过滤透传](web-java-framework-jeecgboot-dict-blacklist-bypass-sqli/) | verified | high | 2026-11-05 |
| [JeecgBoot 拖拽数据集 /drag/onlDragDatasetHead/getTotalData 未授权：tableName 与 config.fieldName 经 FreeMarker 模板拼入 SELECT，直接读取用户口令列](web-java-framework-jeecgboot-drag-gettotaldata-freemarker-sqli/) | verified | high | 2026-11-07 |
| [JeecgBoot 注册接口+FUZZ 出的 addSysUserRole 接口自助提权管理员](web-java-framework-jeecgboot-register-addsysuserrole-admin-escalation/) | verified | high | 2026-11-08 |
| [JFinal ActionMapping.mapping 直接 put 伪造 Action：手搓 Action 对象注册 /controllershell 路由执行任意命令](web-java-framework-jfinal-actionmapping-route-memshell/) | verified | high | 2026-11-08 |
| [JFinal Handler.next 单链表插桩：把恶意 Handler 插到 ActionHandler 之前，按路径前缀命中任意请求执行命令](web-java-framework-jfinal-handler-next-chain-memshell/) | verified | high | 2026-11-08 |
| [JFinal 既有 Action 的 interceptors 字段替换：给指定路由（如 /hello）挂恶意 Interceptor，只有该路径带 cmd 参数才执行](web-java-framework-jfinal-action-interceptors-field-memshell/) | verified | high | 2026-11-08 |
| [MyBatis-Plus ≤3.5.6 UpdateWrapper.eq 列名未过滤：用户可控列名直拼 WHERE 触发 SQL 注入（CVE-2024-35548）](web-java-framework-mybatis-plus-updatewrapper-column-sqli/) | verified | high | 2026-11-09 |
| [Pear Admin Boot 2.0.2 /system/dictData/getDictItems/{dictCode}：三段式 dictCode 直入 ${table}/${text}/${code}，无 WHERE 也能回显 user()（CVE-2024-6241）](web-java-framework-pear-admin-boot-getdictitems-table-text-code-sqli/) | verified | high | 2026-11-08 |
| [RuoYi 4.5.0 /common/download/resource 路径穿越任意文件读取](web-java-framework-ruoyi-download-resource-path-traversal/) | verified | high | 2026-11-05 |
| [RuoYi-Vue-Plus <=5.4.0 sendMessageWithAttachment 任意文件读取：filePath 可控附件经邮件外带](web-java-framework-ruoyi-vue-plus-sendmessagewithattachment-arbitrary-file-read/) | verified | high | 2026-11-07 |
| [Solon <=3.0.8 静态文件映射未过滤 ../：/assets/ 前缀拼接路径穿越读任意文件（CVE-2025-1584）](web-java-framework-solon-staticfiles-path-traversal-arbitrary-file-read/) | verified | high | 2026-11-08 |
| [Solon 框架 Filter 内存马：静态块反射 Context.current 链路取 ChainManager 并 addFilter 执行 cmd](web-java-framework-solon-filter-memshell-chainmanager-reflect/) | verified | high | 2026-11-07 |
| [Solon 路由内存马：Context.current 反查 AppContext，反射 RouterDefault.add 注册 ActionDefault 路由](web-java-framework-solon-route-memshell-routerdefault-add/) | verified | medium | 2026-11-08 |
| [Undertow 运行中定位任意 Filter 实例：当前线程 ThreadLocalMap → ServletRequestContext → deployment.lifecycleObjects → ManagedFilter.filter](web-java-framework-undertow-managedfilter-threadlocal-lifecycle-locate/) | verified | high | 2026-11-08 |
| [XFire /services/* 被认证 Filter 前缀白名单放行：SOAP 终点未授权调用 serviceClass 公共方法](web-java-framework-xfire-services-filter-whitelist-unauth-invoke/) | verified | high | 2026-11-08 |
| [内存马定位：从当前线程对象图按字段名 BFS 搜索框架内部注册表（ChainManager/_router/RouterDefault）](java-memshell-thread-object-graph-field-search/) | verified | medium | 2026-11-08 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
