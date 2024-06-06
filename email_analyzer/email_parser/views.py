import logging
from django.shortcuts import render
from .email_analyzer import analyze_email

logger = logging.getLogger(__name__)

def base(request):
    return render(request,'base.html')

def index(request):
    return render(request, 'parser.html')

def analyze(request):
    if request.method == 'POST':
        logger.debug("Received a POST request")
        if request.FILES.get('eml_file'):
            logger.debug("EML file uploaded")
            eml_file = request.FILES['eml_file']
            result = analyze_email(eml_file)
            logger.debug(f"Analysis result: {result}")
            return render(request, 'results.html', {'result': result})
        else:
            logger.debug("No EML file uploaded")
    else:
        logger.debug("Not a POST request")
    return render(request, 'parser.html')

def contact(request):
    return render(request, 'contact-us.html')