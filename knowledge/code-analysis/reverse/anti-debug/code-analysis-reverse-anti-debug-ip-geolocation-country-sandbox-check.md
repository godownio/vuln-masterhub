---
id: code-analysis-reverse-anti-debug-ip-geolocation-country-sandbox-check
title: 反沙箱：ip-api.com 查询出口 IP 归属地，非目标国家（China）即退出，反制境外云沙箱
type: scenario
domain: code-analysis
path: code-analysis/reverse/anti-debug
technique: ip-geolocation-country-sandbox-filter
aliases:
- IP 归属地反沙箱
- IP 地理检测
- 地域定向反沙箱
- 境外沙箱反制
- ip-api 反分析
tags:
- anti-sandbox
- evasion
- windows
- malware
- ip-geolocation
- cpp
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V444-fix
  verified_at: '2026-11-09T23:15:55+08:00'
  notes: V444 核对指出原理第 4 条臆增原文不存在的内容（本地子进程 curl 探测 IP 因行为特征明显被弃用、改本地语言/区域判断）。已删除该句，仅保留『启动即访问 ip-api 是强行为特征、易被识别』。主体 ip-api.com/csv + find(China) 否则 exit(0) 与 PoC 不变。
---

## 一句话结论

面向国内目标的样本启动时请求 `ip-api.com/csv` 获取出口 IP 归属，响应中不含 `China` 就 `exit(0)`；境外云沙箱/分析集群的出口 IP 落在非目标国家，动态分析拿不到后续行为，代价是启动即对外发 HTTP 请求，暴露明显的网络行为特征。

## 原理

- 在线沙箱（VirusTotal、微步、Any.Run、Joe 等）与安全公司的分析集群大多部署在境外，出口 IP 归属地不是攻击者的目标国家；攻击者用免费 IP 地理 API 判断归属，与目标地域比对即可低成本筛掉这类环境。
- 原文实现：`httplib::Client("http://ip-api.com")` 请求 `/csv`，把整个响应正文拼成字符串后 `find("China") != std::string::npos` 判为国内 IP 并继续，否则 `exit(0)`。`/csv` 的第一列即国家名，实现虽粗糙但对“境外沙箱”有效。
- 该检查同时是网络连通性门控：请求失败/状态非 200 时直接退出，样本在没有外网或 API 被拦截的环境不运行。
- 隐蔽性较差：进程启动即访问 ip-api 这类公共服务是强行为特征，静态/动态分析都容易识别，此类网络探测是明显暴露面。
- 对国内沙箱无效：若目标就在国内（如国内厂商云沙箱使用国内出口），归属判断无法区分真实用户与沙箱，只能反制境外环境。

## 触发条件

- 目标用户/资产位于特定国家（原文为国内，判断字符串 `China`）；
- 样本可出网并访问 `ip-api.com`（或同类 IP 地理 API）；
- 分析环境出口 IP 不在目标国家（境外云沙箱、研究机构）；
- 检查位于下载/解密/执行载荷等敏感行为之前。

## 利用步骤

1. 在载荷逻辑前请求 IP 地理 API（如 `http://ip-api.com/csv`）。
2. 读取响应正文；若状态非 200 或请求失败，直接退出。
3. 在正文中匹配目标国家字符串（原文 `China`）。
4. 命中则继续执行；不命中则 `exit(0)`，样本在境外沙箱中无行为。

## PoC

```cpp
bool check_ip() {
    auto url = "http://ip-api.com";
    httplib::Client cli(url);
    auto res = cli.Get("/csv");
    std::string ip_str;
    if (res->status == 200) {
        for (char c : res->body) ip_str += c;
    } else {
        exit(0);
    }
    if (ip_str.find("China") != std::string::npos) {
        return true;   // 目标国家 IP，继续
    }
    exit(0);           // 非目标国家，视为境外沙箱/非目标
    return false;
}
```

说明：`/csv` 返回形如 `China,Beijing,Beijing,...` 的首列国家信息；原文未给出具体响应样例与完整工程。

## 变体与关联

- 变体：改用 `ip-api.com/json` 解析 `country` 字段（参见 Grandoreiro 加载器的受害者画像用法），比字符串包含更稳。
- 变体：按国家→省/市逐级缩小到地级市，进一步排除异地分析环境；代价是误杀漫游/代理用户。
- 变体：叠加云厂商 IP 段黑名单（AWS/Azure/GCP 出口段），可识别不伪装地域的云沙箱。
- 关联：既有「Grandoreiro 加载器受害者校验」卡用 `ip-api.com/json` 收集国家并比对黑名单，侧重受害者筛选与画像回传；本卡是独立的“非目标国家即退出”反沙箱原子，触发/PoC 更简单。

## 检测与防御

- 检测：样本启动早期访问 `ip-api.com` 等地理 API；流量中出现 `/csv`、`/json` 地理查询；样本在无法访问该 API 时立即退出、在境外出口下无行为。
- 防御/分析侧：沙箱出口伪装到目标国家（或经目标国家代理）；统一阻断/伪造地理 API 响应；结合网络与进程行为综合判定，不依赖单一出口 IP。
- 样本侧取舍：网络探测暴露行为特征，容易被动态规则直接标记；依赖外部 API 可用性，且对国内沙箱无效。
