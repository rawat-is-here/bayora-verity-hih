"""
Fresh check for missing episodes on DramaDunyam
"""

import sys
import json
import urllib.request
import http.cookiejar

try:
    sys.stdout.reconfigure(encoding='utf-8')
except Exception:
    pass

SERIES_ID = "310314"
MISSING_EPS = [8, 22, 32, 33, 35, 37, 38, 43, 47, 48, 50]

HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Referer': f'https://dramadunyam.com/en/series/zombie-apocalypse-trapped-with-3-campus-beauties/episode-1',
    'Accept': 'application/json, text/plain, */*'
}

def main():
    cj = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))

    print("[*] Initializing fresh session...")
    opener.open(urllib.request.Request(
        'https://dramadunyam.com/en/series/zombie-apocalypse-trapped-with-3-campus-beauties/episode-1',
        headers=HEADERS
    ))
    opener.open(urllib.request.Request('https://dramadunyam.com/api/config', headers=HEADERS))
    print("[+] Session initialized.\n")

    results = {}
    for ep in MISSING_EPS:
        url = f'https://dramadunyam.com/play/{SERIES_ID}/{ep}'
        req = urllib.request.Request(url, headers=HEADERS)
        try:
            resp = opener.open(req)
            data = json.loads(resp.read().decode('utf-8'))
            results[ep] = {"status": 200, "data": data}
            print(f"[+] Episode {ep:02d}: AVAILABLE! (Type: {data.get('type')}, URL: {bool(data.get('url'))})")
        except urllib.error.HTTPError as e:
            body = e.read().decode('utf-8', errors='ignore')
            try:
                err_json = json.loads(body)
                results[ep] = {"status": e.code, "reason": err_json}
                print(f"[-] Episode {ep:02d}: HTTP {e.code} -> {err_json}")
            except Exception:
                results[ep] = {"status": e.code, "body": body[:60]}
                print(f"[-] Episode {ep:02d}: HTTP {e.code} -> {body[:60]}")
        except Exception as e:
            results[ep] = {"error": str(e)}
            print(f"[!] Episode {ep:02d}: Error -> {e}")

    available = [ep for ep, r in results.items() if r.get("status") == 200]
    print("\n" + "=" * 50)
    print(f"Check Complete! Newly available episodes: {len(available)} / {len(MISSING_EPS)}")
    if available:
        print(f"Episodes ready to download: {available}")
    else:
        print("None of the missing episodes are ready yet.")
    print("=" * 50)

if __name__ == "__main__":
    main()
