'''
gunicorn -c gunicorn.py vpnmanager.wsgi:application
'''
import os
import multiprocessing

# 设置gunicorn进程名称，ps和top时可以查看
# 需要安装: pip install setproctitle
proc_name = 'vpnmanager'
default_proc_name = 'vpnmanager'
CUR_DIR = os.path.dirname(__file__)

# 设置守护进程,
daemon = 'true'

# 设置进程文件目录
pidfile = '/var/run/vpnmanager.pid'
# 设置访问日志和错误信息日志路径
accesslog = '/var/log/gunicorn_acess.log'
errorlog = '/var/log/gunicorn_info.log'
# 设置日志记录水平
loglevel = 'info'

# 开启几个进程
workers = multiprocessing.cpu_count() * 2
# 每个进程开启几个线程
threads = multiprocessing.cpu_count() * 2
# 每个worker最大处理请求数量, 超过就重启此worker
max_requests = 1000
# 随机增加偏移量range(1, max_requests_jitter)，与max_requests配合，防止多个worker同时重启
max_requests_jitter = 100

bind = "0.0.0.0:8000"
chdir = CUR_DIR
preload = True
worker_class = 'gevent'
