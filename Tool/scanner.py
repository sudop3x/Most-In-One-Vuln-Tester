import requests
import time
import re

COMMON_PATHS = [
    "/admin", "/login", "/config.php", "/.git", "/backup", "/.env",
    "/db_backup", "/test", "/old", "/private", "/data", "/uploads",
    "/tmp", "/wp-admin", "/phpmyadmin", "/api", "/api/v1", "/hidden"
]

JS_LIBS = ["jquery", "angular", "react", "vue"]

META_REFRESH_REGEX = r'<meta http-equiv=["\']refresh["\']'
DEPRECATED_JS_REGEX = r'<script src=["\'].*(jquery|angular|react|vue).*["\']'

def scan_url(url):
    tests = []
    start_total = time.time()
    try:
        res = requests.get(url, timeout=5)
        html_content = res.text
        cookies = res.cookies
        headers = res.headers
    except:
        res = None
        html_content = ""
        cookies = []
        headers = {}

    header_tests = [
        ("Content-Security-Policy","Restricts sources scripts/styles", 
         "Without CSP, XSS attacks are easier", "Add CSP header"),
        ("X-Frame-Options","Prevents clickjacking",
         "Missing allows framing", "Add X-Frame-Options DENY or SAMEORIGIN"),
        ("Strict-Transport-Security","Enforces HTTPS",
         "Without HSTS, site is vulnerable to MITM", "Add HSTS header"),
        ("X-Content-Type-Options","Prevents MIME sniffing",
         "Without it, browser may interpret scripts incorrectly", "Set X-Content-Type-Options: nosniff"),
        ("Referrer-Policy","Controls referrer header",
         "Sensitive URLs may leak", "Set Referrer-Policy: no-referrer")
    ]
    for name, definition, impact, mitigation in header_tests:
        start = time.time()
        result = "Present" if name in headers else "Missing"
        end = time.time()
        tests.append({
            "test_name": name,
            "time_taken": f"{end-start:.2f}s",
            "result": result,
            "definition": definition,
            "impact": impact,
            "mitigation": mitigation,
            "payload": "Checked HTTP headers",
            "notes": f"Checked header {name}"
        })

  
    start = time.time()
    server_val = headers.get("Server","Hidden")
    end = time.time()
    tests.append({
        "test_name":"Server Header Exposure",
        "time_taken":f"{end-start:.2f}s",
        "result":server_val,
        "definition":"Server header can reveal software/version",
        "impact":"Attackers can target known vulnerabilities",
        "mitigation":"Remove/obfuscate Server header",
        "payload":"Read Server header",
        "notes":"Fingerprinting server"
    })


    start = time.time()
    result = "Enabled" if url.startswith("https://") else "Not Enabled"
    end = time.time()
    tests.append({
        "test_name":"HTTPS Enforcement",
        "time_taken":f"{end-start:.2f}s",
        "result":result,
        "definition":"HTTPS ensures secure communication",
        "impact":"Without HTTPS, traffic can be intercepted",
        "mitigation":"Redirect HTTP to HTTPS",
        "payload":"Checked URL scheme",
        "notes":"Basic HTTPS check"
    })


    start = time.time()
    try:
        r = requests.get(url, timeout=5)
        result = "OK"
    except:
        result = "Failed"
    end = time.time()
    tests.append({
        "test_name":"TLS/SSL Check",
        "time_taken":f"{end-start:.2f}s",
        "result":result,
        "definition":"Checks if HTTPS/TLS is active",
        "impact":"Weak TLS or none exposes data",
        "mitigation":"Use modern TLS (1.2+)",
        "payload":"Connection attempt",
        "notes":"Basic TLS handshake check"
    })

   
    xss_payloads = ["<script>alert(1)</script>","<img src=x onerror=alert(1)>","<svg/onload=alert(1)>"]
    for i, payload in enumerate(xss_payloads):
        start = time.time()
        try:
            r = requests.get(url, params={"q":payload}, timeout=5)
            result = "Vulnerable" if payload in r.text else "Safe"
        except:
            result = "Could not test"
        end = time.time()
        tests.append({
            "test_name":f"XSS Test {i+1}",
            "time_taken":f"{end-start:.2f}s",
            "result":result,
            "definition":"Cross-Site Scripting",
            "impact":"Attacker can steal cookies or perform actions",
            "mitigation":"Sanitize input + CSP",
            "payload":payload,
            "notes":"Reflected XSS test"
        })

  
    sql_payloads = ["' OR '1'='1","' UNION SELECT NULL--","' AND SLEEP(1)--"]
    for i, payload in enumerate(sql_payloads):
        start = time.time()
        try:
            r = requests.get(url, params={"q":payload}, timeout=5)
            result = "Vulnerable" if "error" in r.text.lower() or "sql" in r.text.lower() else "Safe"
        except:
            result = "Could not test"
        end = time.time()
        tests.append({
            "test_name":f"SQL Injection {i+1}",
            "time_taken":f"{end-start:.2f}s",
            "result":result,
            "definition":"SQL Injection allows attacker to run queries",
            "impact":"Read/modify database",
            "mitigation":"Use parameterized queries",
            "payload":payload,
            "notes":"Error-based/union-based SQLi test"
        })

   
    start = time.time()
    found_paths=[]
    for path in COMMON_PATHS:
        try:
            r = requests.get(url+path, timeout=3)
            if r.status_code==200:
                found_paths.append(path)
        except:
            pass
    end = time.time()
    tests.append({
        "test_name":"Directory / Common Paths",
        "time_taken":f"{end-start:.2f}s",
        "result":", ".join(found_paths) if found_paths else "None",
        "definition":"Detects sensitive directories",
        "impact":"Exposed files provide info to attackers",
        "mitigation":"Remove/protect paths",
        "payload":", ".join(COMMON_PATHS),
        "notes":"Automated path enumeration"
    })


   
    start=time.time()
    insecure=[]
    for c in cookies:
        if not getattr(c,"secure",False):
            insecure.append(c.name)
    result=", ".join(insecure) if insecure else "None"
    end=time.time()
    tests.append({
        "test_name":"Insecure Cookies",
        "time_taken":f"{end-start:.2f}s",
        "result":result,
        "definition":"Cookies missing Secure/HttpOnly",
        "impact":"Can be stolen via XSS/MITM",
        "mitigation":"Set Secure+HttpOnly",
        "payload":"Analyzed cookies",
        "notes":"Check cookie flags"
    })

   
    start=time.time()
    samesite_missing=[]
    for c in cookies:
        if not getattr(c,"samesite",None):
            samesite_missing.append(c.name)
    result=", ".join(samesite_missing) if samesite_missing else "None"
    end=time.time()
    tests.append({
        "test_name":"Cookies Missing SameSite",
        "time_taken":f"{end-start:.2f}s",
        "result":result,
        "definition":"Cookies should have SameSite flag",
        "impact":"CSRF attacks possible",
        "mitigation":"Add SameSite=Strict/Lax",
        "payload":"Checked all cookies",
        "notes":"CSRF mitigation check"
    })


    start=time.time()
    try:
        r=requests.options(url,timeout=3)
        unsafe=[]
        for m in ["PUT","DELETE","TRACE"]:
            if m in r.headers.get("Allow",""):
                unsafe.append(m)
        result=", ".join(unsafe) if unsafe else "None"
    except:
        result="Could not test"
    end=time.time()
    tests.append({
        "test_name":"Unsafe HTTP Methods",
        "time_taken":f"{end-start:.2f}s",
        "result":result,
        "definition":"Methods that modify resources",
        "impact":"PUT/DELETE/TRACE can allow changes",
        "mitigation":"Disable unsafe methods",
        "payload":"OPTIONS request",
        "notes":"Check Allow header"
    })


    start=time.time()
    emails = re.findall(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", html_content)
    result=", ".join(emails) if emails else "None"
    end=time.time()
    tests.append({
        "test_name":"Email / Sensitive Info",
        "time_taken":f"{end-start:.2f}s",
        "result":result,
        "definition":"Find emails in HTML",
        "impact":"Exposure of sensitive info",
        "mitigation":"Remove emails from HTML",
        "payload":"Parsed HTML content",
        "notes":"Basic email detection"
    })


    start=time.time()
    meta_refresh=re.findall(META_REFRESH_REGEX, html_content, re.I)
    result="Present" if meta_refresh else "None"
    end=time.time()
    tests.append({
        "test_name":"Meta Refresh",
        "time_taken":f"{end-start:.2f}s",
        "result":result,
        "definition":"Detects HTML auto redirects",
        "impact":"Phishing or unwanted redirects",
        "mitigation":"Remove/validate meta refresh",
        "payload":"Scanned HTML head",
        "notes":"Meta refresh tag check"
    })


    start=time.time()
    deprecated_js=re.findall(DEPRECATED_JS_REGEX, html_content, re.I)
    result=", ".join(deprecated_js) if deprecated_js else "None"
    end=time.time()
    tests.append({
        "test_name":"Deprecated JS Libraries",
        "time_taken":f"{end-start:.2f}s",
        "result":result,
        "definition":"Old JS libs may have vulnerabilities",
        "impact":"Attacker can exploit old JS versions",
        "mitigation":"Update libraries",
        "payload":"Parsed <script> src",
        "notes":"Detects jQuery/Angular/React/Vue"
    })


    start=time.time()
    comments = re.findall(r"<!--(.*?)-->", html_content, re.S)
    result=f"{len(comments)} found" if comments else "None"
    end=time.time()
    tests.append({
        "test_name":"HTML Comments",
        "time_taken":f"{end-start:.2f}s",
        "result":result,
        "definition":"Comments may reveal secrets",
        "impact":"Attackers can find sensitive info",
        "mitigation":"Remove comments before production",
        "payload":"Parsed HTML comments",
        "notes":"Basic HTML comment check"
    })


    start=time.time()
    mixed = re.findall(r'https?://', html_content)
    insecure = [url for url in mixed if url.startswith('http://')]
    result=", ".join(insecure) if insecure else "None"
    end=time.time()
    tests.append({
        "test_name":"Mixed Content",
        "time_taken":f"{end-start:.2f}s",
        "result":result,
        "definition":"HTTP content on HTTPS page",
        "impact":"Can be intercepted or modified",
        "mitigation":"Use HTTPS for all resources",
        "payload":"Scanned all resource URLs",
        "notes":"Mixed content check"
    })


    start=time.time()
    forms = re.findall(r'<form[^>]+action=["\'](http://[^"\']+)["\']', html_content, re.I)
    result=", ".join(forms) if forms else "None"
    end=time.time()
    tests.append({
        "test_name":"Forms over HTTP",
        "time_taken":f"{end-start:.2f}s",
        "result":result,
        "definition":"Form submissions should use HTTPS",
        "impact":"Credentials/data can be intercepted",
        "mitigation":"Change form action to HTTPS",
        "payload":"Parsed HTML forms",
        "notes":"HTTP form check"
    })


    start=time.time()
    rredirect_test = requests.get(url, params={"next":"http://evil.com"}, timeout=5)
    if "evil.com" in rredirect_test.text:
        result="Vulnerable"
    else:
        result="Safe"
    end=time.time()
    tests.append({
        "test_name":"Open Redirect",
        "time_taken":f"{end-start:.2f}s",
        "result":result,
        "definition":"Redirection to external URLs",
        "impact":"Phishing or user redirection",
        "mitigation":"Validate redirect URLs",
        "payload":"GET param next=http://evil.com",
        "notes":"Basic open redirect check"
    })


    start=time.time()
    try:
        r = requests.get(url, headers={"X-Test":"injection\r\nInjected-Header:1"}, timeout=3)
        result="Vulnerable" if "Injected-Header" in r.headers else "Safe"
    except:
        result="Could not test"
    end=time.time()
    tests.append({
        "test_name":"Header Injection",
        "time_taken":f"{end-start:.2f}s",
        "result":result,
        "definition":"Server may reflect headers improperly",
        "impact":"Header injection possible",
        "mitigation":"Sanitize headers",
        "payload":"X-Test header with CRLF injection",
        "notes":"Basic header injection test"
    })

  
    start=time.time()
    try:
        r = requests.get(url+"?q='", timeout=5)
        if "traceback" in r.text.lower() or "error" in r.text.lower():
            result="Vulnerable"
        else:
            result="Safe"
    except:
        result="Could not test"
    end=time.time()
    tests.append({
        "test_name":"Error Messages / Stack Trace",
        "time_taken":f"{end-start:.2f}s",
        "result":result,
        "definition":"Detailed server errors reveal info",
        "impact":"Attackers gain internal info",
        "mitigation":"Hide error details in production",
        "payload":"Query parameter with '",
        "notes":"Basic error message check"
    })
   
    start = time.time()
    try:
        r = requests.get(url, headers={"Origin": "http://evil.com"}, timeout=5)
        result = "Vulnerable" if r.headers.get("Access-Control-Allow-Origin") == "*" else "Safe"
    except:
        result = "Could not test"
    end = time.time()
    tests.append({
        "test_name": "CORS Misconfiguration",
        "time_taken": f"{end-start:.2f}s",
        "result": result,
        "definition": "Improper CORS allows any origin to access resources",
        "impact": "Attacker-controlled websites can access sensitive data",
        "mitigation": "Set Access-Control-Allow-Origin to specific domains",
        "payload": "GET with Origin header set to http://evil.com",
        "notes": "Checked Access-Control-Allow-Origin header"
    })

    start = time.time()
    try:
        deprecated_js = re.findall(DEPRECATED_JS_REGEX, html_content, re.I)
        result = ", ".join(deprecated_js) if deprecated_js else "None"
    except:
        result = "Could not test"
    end = time.time()
    tests.append({
        "test_name": "Deprecated JS Libraries",
        "time_taken": f"{end-start:.2f}s",
        "result": result,
        "definition": "Old JS libraries may have known vulnerabilities",
        "impact": "Attackers can exploit outdated libraries",
        "mitigation": "Update to latest versions",
        "payload": "Parsed <script> src tags",
        "notes": "Detected presence of common JS libs (jquery/angular/react/vue)"
    })


    start = time.time()
    try:
        r = requests.get(url, params={"next": "http://evil.com"}, timeout=5)
        result = "Vulnerable" if "evil.com" in r.text or r.history else "Safe"
    except:
        result = "Could not test"
    end = time.time()
    tests.append({
        "test_name": "Open Redirect",
        "time_taken": f"{end-start:.2f}s",
        "result": result,
        "definition": "External redirection without validation",
        "impact": "Phishing or redirecting users to malicious sites",
        "mitigation": "Validate and whitelist redirect parameters",
        "payload": "GET param next=http://evil.com",
        "notes": "Basic open redirect check by sending next param"
    })


    start = time.time()
    try:
        forms = re.findall(r'<form[^>]+action=["\'](http://[^"\']+)["\']', html_content, re.I)
        result = ", ".join(forms) if forms else "None"
    except:
        result = "Could not test"
    end = time.time()
    tests.append({
        "test_name": "Forms over HTTP",
        "time_taken": f"{end-start:.2f}s",
        "result": result,
        "definition": "Form submissions should use HTTPS to protect credentials",
        "impact": "Credentials/data can be intercepted in transit",
        "mitigation": "Ensure form action uses HTTPS or relative URLs",
        "payload": "Scanned form action attributes in HTML",
        "notes": "Detected forms that submit over plain HTTP"
    })


    start = time.time()
    try:
        resources = re.findall(r'(?:src|href)=["\'](http://[^"\']+)["\']', html_content, re.I)
        result = ", ".join(resources) if resources else "None"
    except:
        result = "Could not test"
    end = time.time()
    tests.append({
        "test_name": "Mixed Content",
        "time_taken": f"{end-start:.2f}s",
        "result": result,
        "definition": "HTTP resources loaded on an HTTPS page",
        "impact": "Insecure resources can be intercepted/modified",
        "mitigation": "Serve all resources over HTTPS",
        "payload": "Scanned for http:// resource URLs",
        "notes": "Identifies insecure resource links"
    })


    start = time.time()
    try:
        meta_refresh = re.findall(META_REFRESH_REGEX, html_content, re.I)
        result = "Present" if meta_refresh else "None"
    except:
        result = "Could not test"
    end = time.time()
    tests.append({
        "test_name": "Meta Refresh",
        "time_taken": f"{end-start:.2f}s",
        "result": result,
        "definition": "Detects HTML auto-refresh/redirect meta tags",
        "impact": "Can be abused for phishing or misleading redirects",
        "mitigation": "Avoid meta refresh or validate targets",
        "payload": "Scanned HTML head for meta refresh tags",
        "notes": "Meta refresh tag detection"
    })


    start = time.time()
    try:
        comments = re.findall(r'<!--(.*?)-->', html_content, re.S)
        result = f"{len(comments)} found" if comments else "None"
    except:
        result = "Could not test"
    end = time.time()
    tests.append({
        "test_name": "HTML Comments",
        "time_taken": f"{end-start:.2f}s",
        "result": result,
        "definition": "Comments may contain credentials or notes for developers",
        "impact": "Attackers can discover hidden info in comments",
        "mitigation": "Remove sensitive comments from production HTML",
        "payload": "Parsed HTML comments",
        "notes": "Counts number of HTML comments"
    })


    start = time.time()
    try:
        extra_paths = ["/.env", "/backup.zip", "/.htpasswd", "/oldsite"]
        found_extra = []
        for path in extra_paths:
            try:
                r = requests.get(url + path, timeout=3)
                if r.status_code == 200:
                    found_extra.append(path)
            except:
                pass
        result = ", ".join(found_extra) if found_extra else "None"
    except:
        result = "Could not test"
    end = time.time()
    tests.append({
        "test_name": "Extra Sensitive Paths",
        "time_taken": f"{end-start:.2f}s",
        "result": result,
        "definition": "Detects extra sensitive files that may expose secrets",
        "impact": "Exposed files can leak credentials or configs",
        "mitigation": "Remove or secure these files",
        "payload": "Checked paths: /.env, /backup.zip, /.htpasswd, /oldsite",
        "notes": "Additional path enumeration"
    })


    start = time.time()
    try:
        json_paths = ["/api", "/api/v1", "/api/data"]
        found_json = []
        for p in json_paths:
            try:
                r = requests.get(url + p, timeout=3)
                if r.status_code == 200 and 'application/json' in r.headers.get('Content-Type', ''):
                    found_json.append(p)
            except:
                pass
        result = ", ".join(found_json) if found_json else "None"
    except:
        result = "Could not test"
    end = time.time()
    tests.append({
        "test_name": "JSON Endpoints",
        "time_taken": f"{end-start:.2f}s",
        "result": result,
        "definition": "Detects exposed JSON API endpoints",
        "impact": "APIs may leak data if unauthenticated",
        "mitigation": "Require authentication and rate-limit APIs",
        "payload": "Checked common API paths",
        "notes": "Basic API discovery"
    })


    start = time.time()
    try:
        frame_headers = ["X-Frame-Options", "Content-Security-Policy"]
        result = "Vulnerable" if all(h not in headers for h in frame_headers) else "Safe"
    except:
        result = "Could not test"
    end = time.time()
    tests.append({
        "test_name": "Clickjacking Protection",
        "time_taken": f"{end-start:.2f}s",
        "result": result,
        "definition": "Checks if site prevents framing",
        "impact": "Without protection, site can be embedded in frames",
        "mitigation": "Add X-Frame-Options or CSP frame-ancestors",
        "payload": "Checked X-Frame-Options and CSP frame-ancestors",
        "notes": "Frame protection header check"
    })

    start = time.time()
    try:
        deprecated_meta = re.findall(r'<meta[^>]+http-equiv=["\']X-UA-Compatible["\']', html_content, re.I)
        result = "Present" if deprecated_meta else "None"
    except:
        result = "Could not test"
    end = time.time()
    tests.append({
        "test_name": "Deprecated Meta Tags",
        "time_taken": f"{end-start:.2f}s",
        "result": result,
        "definition": "Detects old/obsolete meta tags",
        "impact": "May indicate outdated site or compatibility issues",
        "mitigation": "Remove deprecated meta tags",
        "payload": "Parsed HTML meta tags",
        "notes": "Checks for X-UA-Compatible"
    })


    start = time.time()
    try:
        hsts = headers.get("Strict-Transport-Security", "")
        result = hsts if hsts else "Missing"
    except:
        result = "Could not test"
    end = time.time()
    tests.append({
        "test_name": "HSTS Max-Age",
        "time_taken": f"{end-start:.2f}s",
        "result": result,
        "definition": "Checks HSTS header to enforce HTTPS",
        "impact": "Missing/short HSTS increases MITM risk",
        "mitigation": "Set Strict-Transport-Security with long max-age",
        "payload": "Read Strict-Transport-Security header",
        "notes": "HSTS header presence and value"
    })


    start = time.time()
    try:
        server_val = headers.get("Server", "Hidden")
        result = server_val
    except:
        result = "Could not test"
    end = time.time()
    tests.append({
        "test_name": "Server Version Exposure",
        "time_taken": f"{end-start:.2f}s",
        "result": result,
        "definition": "Exposes server software/version",
        "impact": "Helps attackers identify exploits",
        "mitigation": "Hide or obfuscate server version",
        "payload": "Read Server header",
        "notes": "Server fingerprinting"
    })

    start = time.time()
    try:
        xpb = headers.get("X-Powered-By", "None")
        result = xpb
    except:
        result = "Could not test"
    end = time.time()
    tests.append({
        "test_name": "X-Powered-By Header",
        "time_taken": f"{end-start:.2f}s",
        "result": result,
        "definition": "Exposes underlying technology (e.g., PHP, Express)",
        "impact": "Information disclosure",
        "mitigation": "Remove X-Powered-By header",
        "payload": "Read X-Powered-By header",
        "notes": "Technology disclosure check"
    })


    start = time.time()
    try:
        r = requests.get(url, timeout=5)
        result = "Valid" if r.status_code == 200 else "Invalid"
    except:
        result = "Invalid"
    end = time.time()
    tests.append({
        "test_name": "TLS Certificate Validity",
        "time_taken": f"{end-start:.2f}s",
        "result": result,
        "definition": "Checks if TLS certificate is valid",
        "impact": "Invalid certs can enable MITM attacks",
        "mitigation": "Use a trusted certificate authority",
        "payload": "HTTPS request",
        "notes": "Basic TLS validity check"
    })


    start = time.time()
    try:
        deprecated_attrs = re.findall(r'<[^>]+(?:bgcolor|align|border)[^>]*>', html_content, re.I)
        result = f"{len(deprecated_attrs)} found" if deprecated_attrs else "None"
    except:
        result = "Could not test"
    end = time.time()
    tests.append({
        "test_name": "Deprecated HTML Attributes",
        "time_taken": f"{end-start:.2f}s",
        "result": result,
        "definition": "Detects old HTML attributes indicating legacy markup",
        "impact": "Older code may be insecure or unsupported",
        "mitigation": "Update HTML to modern standards",
        "payload": "Parsed HTML tags for deprecated attributes",
        "notes": "Counts deprecated attributes"
    })


    start = time.time()
    try:
        r = requests.get(url + "/sitemap.xml", timeout=5)
        result = "Found" if r.status_code == 200 else "Not Found"
    except:
        result = "Could not test"
    end = time.time()
    tests.append({
        "test_name": "Sitemap XML Check",
        "time_taken": f"{end-start:.2f}s",
        "result": result,
        "definition": "Checks if sitemap.xml is accessible",
        "impact": "Sitemap exposes site structure to crawlers/attackers",
        "mitigation": "Avoid listing sensitive URLs in sitemap",
        "payload": "GET /sitemap.xml",
        "notes": "Sitemap accessibility"
    })


    start = time.time()
    try:
        ssl_header = headers.get("Strict-Transport-Security", "Missing")
        result = ssl_header
    except:
        result = "Could not test"
    end = time.time()
    tests.append({
        "test_name": "SSL Labs Header",
        "time_taken": f"{end-start:.2f}s",
        "result": result,
        "definition": "Checks headers relevant to SSL Labs scoring",
        "impact": "Missing headers reduce TLS configuration score",
        "mitigation": "Add HSTS and other TLS-related headers",
        "payload": "Read TLS-related headers",
        "notes": "Basic SSL header presence check"
    })


    start = time.time()
    try:
        r = requests.get(url + "/robots.txt", timeout=5)
        if r.status_code == 200:
            sensitive = re.findall(r'Disallow:\s*/([^\s]*)', r.text)
            result = ", ".join(sensitive) if sensitive else "None"
        else:
            result = "Not Found"
    except:
        result = "Could not test"
    end = time.time()
    tests.append({
        "test_name": "Robots.txt Sensitive Paths",
        "time_taken": f"{end-start:.2f}s",
        "result": result,
        "definition": "Checks which paths are disallowed for crawlers",
        "impact": "Exposes hidden directories to attackers",
        "mitigation": "Limit disallowed paths to non-sensitive resources",
        "payload": "GET /robots.txt",
        "notes": "Sensitive directories listed in robots.txt"
    })
    


    for path in ["/robots.txt","/sitemap.xml"]:
        start = time.time()
        try:
            r=requests.get(url+path,timeout=5)
            content=r.text if r.status_code==200 else "Not Found"
        except:
            content="Could not fetch"
        end = time.time()
        tests.append({
            "test_name":path[1:]+" Check",
            "time_taken":f"{end-start:.2f}s",
            "result":content,
            "definition":"Crawler instructions/sitemap",
            "impact":"Sensitive paths may be discovered",
            "mitigation":"Expose only non-sensitive paths",
            "payload":"Requested "+path,
            "notes":"Basic content check"
        })




    total_time = time.time() - start_total
    return tests, f"{total_time:.2f}s"