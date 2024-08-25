from django.shortcuts import render
from .models import FileHash
import hashlib
import requests

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

                if not isinstance(hybrid_analysis_result, dict):
                    hybrid_analysis_result = {"error": "Invalid response format from Hybrid Analysis"}

                filehash = FileHash(
                    hash=hash,
                    virustotal_status=virustotal_result,
                    hybrid_analysis_status=hybrid_analysis_result
                )
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
        if response.status_code == 404:
            return {"error": "No encontrado en VirusTotal"}
        response.raise_for_status()
        result = response.json()
        if 'data' not in result or 'attributes' not in result['data']:
            return {"error": "No encontrado en VirusTotal"}
        analysis_results = result['data']['attributes'].get('last_analysis_results', {})
        return analysis_results if analysis_results else {"error": "No encontrado en VirusTotal"}
    except requests.exceptions.RequestException as e:
        return {"error": f"Error comprobando VirusTotal: {e}"}
    
def check_hybrid_analysis(hash):
    url = "https://www.hybrid-analysis.com/api/v2/search/hash"
    headers = {
        "api-key": "efxiparge3d8de76schlsubiff255532zp29p8jwc2dd9af9thj6o3cz17bd0020",
        "accept": "application/json",
        "Content-Type": "application/x-www-form-urlencoded"
    }
    
    data = f"hash={hash}"
    
    try:
        response = requests.post(url, headers=headers, data=data)
        response.raise_for_status()
        result = response.json()
        
        if not result:
            return {"error": "No encontrado en Hybrid Analysis"}
        
        report = result[0] if isinstance(result, list) else result
        
        engines = []
        for engine_key, engine_result in report.get('scan_results', {}).get('scan_details', {}).items():
            engines.append({
                "name": engine_result.get("engine_name", engine_key),
                "result": engine_result.get("threat_found", "Ninguno")
            })

        malicious_indicators = [{"technique": ind.get("technique", "Unknown"), "tactic": ind.get("tactic", "Unknown")} for ind in report.get('malicious_indicators', [])]
        suspicious_indicators = [{"technique": ind.get("technique", "Unknown"), "tactic": ind.get("tactic", "Unknown")} for ind in report.get('suspicious_indicators', [])]

        summary = {
            "sha256": report.get("sha256"),
            "submit_name": report.get("submit_name"),
            "verdict": report.get("verdict", "unknown"),
            "threat_level": report.get("threat_level", "unknown"),
            "vx_family": report.get("vx_family", "unknown"),
            "av_detect": len([e for e in engines if e["result"] != "Ninguno"]),
            "engines": engines,
            "malicious_indicators": malicious_indicators,
            "suspicious_indicators": suspicious_indicators
        }

        return summary
    
    except requests.exceptions.RequestException as e:
        return {"error": f"Error al enviar a Hybrid Analysis: {e}"}
