from django.shortcuts import render
from vpnmanager import settings
# Create your views here.

def JobLogView(request):
    log_file = settings.logfile_path
    # log_content += [line for line in open(log_file, 'r', encoding='UTF-8')]
    with open(log_file,'r',encoding='utf-8') as log:
        log_content = log.readlines()
    context = {
        'page_name': 'vpn连接日志',
        'log_content': log_content,
    }
    if request.method == 'GET':
        return render(request, "joblog.html", context=context)