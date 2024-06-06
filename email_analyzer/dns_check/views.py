import dns.resolver
from django.shortcuts import render

def fetch_dns_info(domain):
    record_types = ['A', 'AAAA', 'MX', 'NS', 'CNAME', 'SOA', 'TXT', 'PTR']
    dns_info = {}
    for record_type in record_types:
        try:
            answer = dns.resolver.resolve(domain, record_type, raise_on_no_answer=False)
            if answer:
                dns_info[record_type] = [str(rdata) for rdata in answer]
        except Exception as e:
            dns_info[record_type] = [str(e)]
    return dns_info

def dns_check(request):
    records = {}
    domain = None
    if request.method == 'POST':
        domain = request.POST.get('domain')
        records = fetch_dns_info(domain)

    return render(request, 'dns_records.html', {'records': records ,'domain': domain})
