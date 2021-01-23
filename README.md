# 1. l2tp over ipsec web manager

## 环境

* Django 3.1.2
* Python 3.8.3



## 1.1. 普通用户权限
* 权限验证登录
* 使用说明
* 用户详情信息

## 1.2. administrator权限

* 可对任何用户进行增删改查

* 可查看普通用户登录日志

[http://vpnmanager.limikeji.com/logviews/](http://vpnmanager.limikeji.com/logviews/)

## 虚拟环境：
```
[root@ali-prod-ops-vpn ~]# cd /alidata/virtualenv/bin/
[root@ali-prod-ops-vpn /alidata/virtualenv/bin]# source activate
```

##### 1.2.1.1.1. 启动方式：
 `gunicorn -c gunicorn.py -D vpnmanager.wsgi:application`

### 日志

```bash
##################################
Now User cuijianzhe is connected!!!
##################################
time: 2020-11-19_16:06:31
clientIP:
username: cuijianzhe
device: ppp0
vpnIP: 192.168.42.1
assignIP: 192.168.42.10
#####################################
Now User cuijianzhe is disconnected!!!
#####################################
time: 2020-11-19_16:07:51
clientIP:
username: cuijianzhe
device: ppp0
vpnIP: 192.168.42.1
assignIP: 192.168.42.10
connect time: 80 s
bytes sent: 248488 B
bytes rcvd: 84293 B
bytes sum: .31 MB
average speed: 4.06 KB/s
```
