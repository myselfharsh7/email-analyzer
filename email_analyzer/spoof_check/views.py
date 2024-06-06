from django.shortcuts import render
import emailprotectionslib.dmarc as dmarc_lib
import emailprotectionslib.spf as spf_lib

def check_records(domain):
    records = {
        'domain': domain,
        'spf': False,
        'spf_details': '',
        'spf_all_present': False,
        'dmarc': False,
        'dmarc_details': '',
        'dmarc_enforced': False,
        'spoofable': True
    }

    # Check SPF
    spf_record = spf_lib.SpfRecord.from_domain(domain)
    if spf_record and spf_record.record:
        records['spf'] = True
        records['spf_details'] = spf_record.record
        records['spf_all_present'] = spf_record.all_string in ['~all', '-all']

    # Check DMARC
    dmarc_record = dmarc_lib.DmarcRecord.from_domain(domain)
    if dmarc_record and dmarc_record.record:
        records['dmarc'] = True
        records['dmarc_details'] = dmarc_record.record
        records['dmarc_enforced'] = 'p=reject' in dmarc_record.record 
    # Determine spoofability
    if records['spf'] and records['dmarc'] and records['spf_all_present'] and records['dmarc_enforced']:
        records['spoofable'] = False

    return records

def spoof_check(request):
    records = None
    if request.method == 'POST':
        domain = request.POST.get('host')
        records = check_records(domain)
    return render(request, 'spoof_check.html', {'records': records})
