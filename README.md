# 1. l2tp over ipsec web manager

## 1.1. 普通用户权限
* 权限验证登录
* 使用说明
* 用户详情信息

## 1.2. administrator权限
* 可对任何用户进行增删改查
* 可查看普通用户登录日志

![](https://github.com/cuijianzhe/l2tp-over-ipsec-web-manager/blob/master/images/admin.png?raw=true)

##### 1.2.1.1.1. 启动方式：
```
nohup /usr/local/bin/python3 /data/l2tp-over-ipsec/manage.py runserver 0.0.0.0:8000 >>/var/log/web_l2tp.log 2<&1 &
```