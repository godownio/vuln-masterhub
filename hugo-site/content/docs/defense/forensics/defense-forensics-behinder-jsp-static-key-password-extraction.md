---
id: defense-forensics-behinder-jsp-static-key-password-extraction
title: 冰蝎 JSP WebShell 静态取证：按约 2.6KB 体积定位并从 xc/pass 提取 AES key 与连接密码
type: scenario
domain: defense
path: defense/forensics
technique: behinder-jsp-static-key-password-extraction
tags:
- forensics
- webshell
- behinder
- jsp
- incident-response
- file-size
- aes-key
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V168
  verified_at: '2026-11-06T09:50:06+08:00'
  notes: 已对照原文Q2与截图核对：faiz.jsp 2616字节、String xc="3c6e0b8a9c15224a"、String pass="pass"、AES解密流程一致；未验证点：未连接冰蝎、未解密真实流量。
url: /docs/defense/forensics/defense-forensics-behinder-jsp-static-key-password-extraction/
draft: false
kb_aliases:
- 冰蝎 JSP 静态分析
- 冰蝎 key 提取
- xc pass 冰蝎马
- 冰蝎文件大小 2600
- Behinder JSP 源码取证
- WebShell 体积初筛
---

## 一句话结论

在失陷 Web 目录中，冰蝎 v2/v3 的 JSP 马体积通常集中在约 2600 字节（常见 2615～2620），按体积与修改时间初筛后读取源码，可直接从 `String xc="..."` 取得 16 字节 AES key、从 `String pass="..."` 取得连接密码，用于复现连接或离线解密流量。

## 原理

- 冰蝎 JSP 服务端需要同时持有对称密钥与连接密码：典型实现把 16 字节 AES key 硬编码在 `String xc` 字段，把请求参数名/密码放在 `String pass` 字段；请求体用 `pass` 作为参数名传入 Base64 密文，服务端用 `xc` 做 AES 解密后反射加载 Java 插件类。
- 不同冰蝎版本/同一版本生成的 JSP 马结构高度相似，文件体积稳定在 2600 字节左右；而正常业务 JSP、Tomcat 自带示例与管理页面的体积分布不同，因此体积是低成本初筛特征。
- WebShell 的 mtime 通常与入侵时间窗、PUT 上传时间或访问日志中的首次请求时间吻合；结合 `ls -l` 的时间列可快速缩小范围。
- 拿到 `xc`/`pass` 后，冰蝎客户端可直接用该密钥/密码连接（需授权）；流量侧则可用 `xc` 作为 AES key 解密历史请求，还原攻击者执行的命令与上传文件。
- 注意该手法针对**未魔改密钥逻辑**的冰蝎 JSP；魔改马可能改为动态密钥、从 session/请求派生 key，或使用 CBC/异或等不同实现，需要按源码调整。

## 触发条件

- 已获得 Web 目录读取权限（容器 shell、主机文件系统、备份或镜像）。
- WebShell 文件未被删除，且能读取源码。
- 目标为冰蝎 v2/v3 的 JSP 马，密钥硬编码在 `xc`、密码在 `pass`。
- 如需解密流量，还需对应的请求/响应数据包。

## 利用步骤

1. 列出 Web 根目录及子目录 JSP：`ls -l --time-style=long-iso`，按大小与时间排序。
2. 筛出体积约 2600 字节（2615～2620）且 mtime 落在入侵时间窗的文件；对每个候选读取头部与关键变量。
3. `grep -nE 'String (xc|pass)' <file>` 或直接 `cat`，记录 16 位 `xc` 与 `pass`。
4. 用 `xc` 作为 AES key、`pass` 作为连接密码，在授权环境用冰蝎客户端验证连接；或对捕获的请求体做 Base64 解码 + AES 解密。
5. 结合文件 mtime、访问日志与容器层时间，确认上传时间与攻击者 IP；保留样本哈希与源码截图作为证据。
6. 排查同目录其他同体积 JSP，攻击者常一次上传多个马或备份副本。

## PoC

```bash
# 1) 按大小和时间列出 Web 目录
docker exec -it tomcat_analysis ls -l --time-style=long-iso /usr/local/tomcat/webapps/ROOT/
# -rw-r--r-- 1 root root 2616 Nov 27 03:39 faiz.jsp
# -rw-r--r-- 1 root root 2620 Nov 27 03:39 hMS8xu.jsp
# -rw-r--r-- 1 root root 2615 Aug 25 09:03 jj.jsp

# 2) 提取冰蝎 key 与密码
docker exec -it tomcat_analysis grep -nE 'String (xc|pass)' /usr/local/tomcat/webapps/ROOT/faiz.jsp
# String xc="3c6e0b8a9c15224a"; String pass="pass";
```

```python
# 3) 用 xc 解密冰蝎 JSP 流量（AES/ECB/PKCS5Padding 为常见实现之一）
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

key = b"3c6e0b8a9c15224a"          # 从 String xc 取得
body = base64.b64decode("<POST body>")
plain = unpad(AES.new(key, AES.MODE_ECB).decrypt(body), 16)
print(plain[:8])                    # 若为 b"\xca\xfe\xba\xbe" 则是 Java class 插件
```

## 变体与关联

- 冰蝎 PHP 马的 key 常以明文写在马文件中，解密方式不同，见 [[defense-forensics-behinder-php-webshell-traffic-decrypt]]。
- 冰蝎 JSP 内存马的 key 可能由密码 MD5 前 16 位派生（`md5(password).hexdigest()[:16]`），见 [[defense-forensics-behinder-jsp-md5-password-key-traffic-decrypt]]；本卡针对源码中硬编码 `xc` 的落地马。
- 哥斯拉 JSP 马的体积与密钥位置不同，见 [[defense-forensics-godzilla-java-webshell-traffic-decode]]。
- 变体：魔改马可能把 key/pass 拆分、编码或从配置读取；应先通读源码再决定解密参数。

## 检测与防御

- Web 目录文件完整性监控：告警新增 JSP、体积集中在 2.6KB 左右的文件、以及批量同尺寸文件。
- WAF/日志检测 PUT 上传 JSP、异常后缀与上传后立即访问的行为；保持 Tomcat `readonly=true`。
- 部署 WebShell 静态扫描（匹配 `xc`、`pass`、`getParameter(pass)`、`ClassLoader.defineClass`、`base64Decode` 等冰蝎特征）。
- 事件响应时保留样本与哈希，提取密钥/密码后离线解密流量，还原命令与横向痕迹，再清除 WebShell 与关联内存马。
