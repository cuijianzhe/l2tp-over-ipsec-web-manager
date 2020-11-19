from django.shortcuts import render
from vpnmanager import settings
# Create your views here.

def JobLogView(request):
    log_file = settings.logfile_path
    log_content = []

    log_content += [line for line in open(log_file, 'r', encoding='UTF-8')]

    context = {
        'page_name': '作业日志',
        'log_content': log_content,
    }
    if request.method == 'GET':
        return render(request, "joblog.html", context=context)