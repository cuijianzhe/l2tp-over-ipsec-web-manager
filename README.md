# 1. l2tp over ipsec web manager

# L2TP-OVER-IPSEC-Manager-Web
**l2tp over ipsec 账户管理系统**
**说明: 该软件为管理l2tp服务在使用前请先自行安装好l2tp over ipsec服务，直接读取你l2tp和ipsec的配置文件，在使用时需要安装python3.7环境具体看下面步骤:**

```
#秘钥配置文件
/etc/ppp/chap-secrets
/etc/ipsec.d/passwd
```

安装L2TP over IPSEC 参考 [这里](https://github.com/hwdsl2/setup-ipsec-vpn)和[这里](https://github.com/xelerance/xl2tpd)

1、安装python环境；

请自行安装 Python3.7环境+Django环境，可用nginx代理

2、安装Django；

```
pip3 install django
#django版本
D:\>python
Python 3.7.1 (v3.7.1:260ec2c36a, Oct 20 2018, 14:57:15) [MSC v.1915 64 bit (AMD64)] on win32
Type "help", "copyright", "credits" or "license" for more information.
>>> import django
>>> print(django.VERSION)
(3, 0, 6, 'final', 0)
```



## 1.1. 普通用户权限
* 权限验证登录
* 使用说明
* 用户详情信息

## 1.2. administrator权限

![](https://github.com/cuijianzhe/l2tp-over-ipsec-web-manager/blob/master/images/admin.png?raw=true)

* 可对任何用户进行增删改查

![]()

![](https://github.com/cuijianzhe/l2tp-over-ipsec-web-manager/blob/master/images/edit.png?raw=true)

* 可查看普通用户登录日志

![](https://github.com/cuijianzhe/l2tp-over-ipsec-web-manager/blob/master/images/logfile.png?raw=true)



##### 1.2.1.1.1. 启动方式：
```
nohup /usr/local/bin/python3 /data/l2tp-over-ipsec/manage.py runserver 0.0.0.0:8000 >>/var/log/web_l2tp.log 2<&1 &
```