from django.shortcuts import render
from .models import FileHash
import hashlib
import json
import requests
import time

def handle_uploaded_file(f):
    hasher = hashlib.sha256()
    for chunk in f.chunks():
        hasher.update(chunk)
    return hasher.hexdigest()

def file_upload(request):
    if request.method == 'POST':
        files = request.FILES.getlist('file')
        results = []
        for file in files:
            hash = handle_uploaded_file(file)
            filehash = FileHash.objects(hash=hash).first()
            if not filehash:
                virustotal_result = check_virustotal(hash)
                hybrid_analysis_result = check_hybrid_analysis(hash)
                filehash = FileHash(hash=hash, virustotal_status=virustotal_result, hybrid_analysis_status=hybrid_analysis_result)
                filehash.save()
            else:
                virustotal_result = filehash.virustotal_status
                hybrid_analysis_result = filehash.hybrid_analysis_status
            
            results.append({
                'hash': hash,
                'virustotal_result': virustotal_result,
                'hybrid_analysis_result': hybrid_analysis_result
            })
        return render(request, 'fileupload/result.html', {'results': results})
    return render(request, 'fileupload/upload.html')

def hash_search(request):
    if request.method == 'POST':
        hash = request.POST.get('hash')
        results = FileHash.objects.filter(hash=hash)
        return render(request, 'fileupload/search_result.html', {'results': results})
    return render(request, 'fileupload/search.html')

def check_virustotal(hash):
    url = f"https://www.virustotal.com/api/v3/files/{hash}"
    headers = {
        "x-apikey": "d73434cd03abf9eafcca59c206b6914832468ee7a788ba990286a391e863caa8"
    }
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        result = response.json()
        data = {
            'id': result.get('data', {}).get('id'),
            'type': result.get('data', {}).get('type'),
            'attributes': result.get('data', {}).get('attributes', {})
        }
        analysis_results = data['attributes'].get('last_analysis_results', {})
        return analysis_results
    except requests.exceptions.RequestException as e:
        return {"error": f"Error checking VirusTotal: {e}"}

def check_hybrid_analysis(hash):
    url = "https://www.hybrid-analysis.com/api/v2/search/hash"
    headers = {
        "User-Agent": "Falcon Sandbox",
        "api-key": "efxiparge3d8de76schlsubiff255532zp29p8jwc2dd9af9thj6o3cz17bd0020",
        "Accept": "application/json",
    }
    data = {
        "hash": hash,
    }
    try:
        response = requests.post(url, headers=headers, data=data)
        response.raise_for_status()
        result = response.json()
        return result
    except requests.exceptions.RequestException as e:
        return {"error": f"Error checking Hybrid Analysis: {e}"}


