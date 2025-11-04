import requests
import json
import whois
import socket
import ssl
import re
import datetime
import math
from urllib.parse import urlparse
from googleapiclient.discovery import build
from fpdf import FPDF
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score

def get_subdomains(domain):
    try:
        response = requests.get(f"https://crt.sh/?q=%.{domain}&output=json", timeout=10)
        if response.status_code == 200:
            subdomains = set()
            for entry in response.json():
                subdomains.add(entry["name_value"])
            return list(subdomains)
        else:
            return []
    except Exception as e:
        print(f"Error getting subdomains: {e}")
        return []

def get_whois_info(domain, whois_key=None):
    if whois_key:
        try:
            url = f"https://api.apilayer.com/whois/{domain}"
            headers = {"apikey": whois_key}
            response = requests.get(url, headers=headers, timeout=10)
            if response.status_code == 200:
                return response.json()
            else:
                print(f"Whois API error: {response.status_code}")
                return None
        except Exception as e:
            print(f"Error getting Whois info via API: {e}")
            return None
    else:
        try:
            # Add timeout to avoid hanging
            import socket
            socket.setdefaulttimeout(10)
            return whois.whois(domain)
        except Exception as e:
            print(f"Error getting Whois info: {e}")
            return None

def get_ip_address(domain):
    try:
        # Get all A records
        addrinfo = socket.getaddrinfo(domain, None, socket.AF_INET, socket.SOCK_STREAM)
        ips = [info[4][0] for info in addrinfo]
        return list(set(ips))  # unique IPs
    except Exception as e:
        print(f"Error getting IP address: {e}")
        return None

def get_abuseipdb_info(ip_address, api_key):
    try:
        url = f"https://api.abuseipdb.com/api/v2/check"
        headers = {
            "Accept": "application/json",
            "Key": api_key
        }
        params = {
            "ipAddress": ip_address,
            "maxAgeInDays": 90
        }
        response = requests.get(url, headers=headers, params=params)
        if response.status_code == 200:
            data = response.json()
            return data.get("data", {})
        else:
            print(f"AbuseIPDB API error: {response.status_code}")
            return None
    except Exception as e:
        print(f"Error getting AbuseIPDB info: {e}")
        return None

def google_search(domain, api_key, cse_id):
    try:
        service = build("customsearch", "v1", developerKey=api_key)
        # Advanced search queries to find potential fake websites and domains
        queries = [
            f'site:{domain} "login"',
            f'site:{domain} "secure"',
            f'site:{domain} "account"',
            f'site:{domain} "webmail"',
            f'site:{domain} "support"',
            f'site:{domain} "billing"',
            f'site:{domain} "update"',
            f'site:{domain} "download"',
            f'inurl:{domain} "powered by"',
            f'"{domain}" phishing',
            f'"{domain}" scam',
            f'"{domain}" fake',
            f'"{domain}" malware',
            f'"{domain}" suspicious',
            f'"{domain}" report',
        ]
        results = []
        for query in queries:
            res = service.cse().list(q=query, cx=cse_id).execute()
            if "items" in res:
                for item in res["items"]:
                    results.append({
                        "title": item.get("title", ""),
                        "link": item.get("link", ""),
                        "snippet": item.get("snippet", "")
                    })
        return results
    except Exception as e:
        print(f"Error performing Google search: {e}")
        return []

def scrape_with_scraperapi(url, api_key):
    try:
        payload = {"api_key": api_key, "url": url}
        response = requests.get("http://api.scraperapi.com", params=payload)
        if response.status_code == 200:
            return response.text
        else:
            print(f"ScraperAPI error: {response.status_code}")
            return None
    except Exception as e:
        print(f"Error scraping with ScraperAPI: {e}")
        return None

def save_to_json(data, filename):
    with open(filename, "w") as f:
        json.dump(data, f, indent=4)

class PDF(FPDF):
    def header(self):
        self.set_font("Helvetica", "B", 12)
        self.cell(0, 10, "Phishing and Malicious URL Detector Report", 0, 1, "C")

    def chapter_title(self, title):
        self.set_font("Helvetica", "B", 12)
        self.cell(0, 10, title, 0, 1, "L")
        self.ln(10)

    def chapter_body(self, body):
        self.set_font("Helvetica", "", 12)
        self.multi_cell(0, 10, body)
        self.ln()

def save_to_pdf(data, filename):
    pdf = PDF()
    pdf.add_page()
    for key, value in data.items():
        pdf.chapter_title(key)
        if isinstance(value, list):
            for item in value:
                pdf.chapter_body(str(item))
        elif isinstance(value, dict):
            for k, v in value.items():
                pdf.chapter_body(f"{k}: {v}")
        else:
            pdf.chapter_body(str(value))
    pdf.output(filename, "F")

# --------------------------
# New functions from phish_detector.py
# --------------------------

def extract_domain(url):
    if not re.match(r'^[a-zA-Z]+://', url):
        url = 'http://' + url
    parsed = urlparse(url)
    host = parsed.hostname or ''
    # strip port if present
    return host.lower()

def levenshtein(a, b):
    # pure python Levenshtein distance
    if a == b:
        return 0
    la, lb = len(a), len(b)
    if la == 0:
        return lb
    if lb == 0:
        return la
    # initialize matrix
    prev = list(range(lb + 1))
    for i, ca in enumerate(a, start=1):
        curr = [i] + [0] * lb
        for j, cb in enumerate(b, start=1):
            cost = 0 if ca == cb else 1
            curr[j] = min(prev[j] + 1,      # deletion
                          curr[j-1] + 1,    # insertion
                          prev[j-1] + cost) # substitution
        prev = curr
    return prev[lb]

def is_punycode(domain):
    return any(part.startswith('xn--') for part in domain.split('.'))

def has_non_ascii(domain):
    try:
        domain.encode('ascii')
        return False
    except UnicodeEncodeError:
        return True

def get_ssl_cert_info(hostname, port=443, timeout=5):
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                return cert
    except Exception as e:
        return None

def age_days_from_whois(domain, whois_key=None):
    try:
        w = get_whois_info(domain, whois_key)
        if not w:
            return None
        # Handle API response or library response
        if whois_key and isinstance(w, dict):
            # API response: look for 'creation_date' or similar
            cd_str = w.get('creation_date') or w.get('created')
            if cd_str:
                # Parse date string, e.g., "2020-01-01T00:00:00Z"
                try:
                    cd = datetime.datetime.fromisoformat(cd_str.replace('Z', '+00:00'))
                    diff = datetime.datetime.utcnow() - cd
                    return diff.days
                except ValueError:
                    return None
        else:
            # Library response
            cd = w.creation_date
            if isinstance(cd, list):
                cd = cd[0]
            if isinstance(cd, datetime.datetime):
                diff = datetime.datetime.utcnow() - cd
                return diff.days
    except Exception:
        return None
    return None

def suspicious_tld(domain):
    # some TLDs are often abused (example list, not exhaustive)
    suspicious_list = {'.tk', '.ml', '.ga', '.cf', '.gq'}  # free-ish TLDs often abused
    for t in suspicious_list:
        if domain.endswith(t):
            return True
    return False

def is_url_shortener(domain):
    # Common URL shorteners
    shorteners = {'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd', 'buff.ly', 'adf.ly', 'bit.do', 'mcaf.ee'}
    return domain in shorteners

def analyze_html_for_forms(html, base_domain):
    """
    Look for <form> tags and check action attributes.
    If action posts to external domain or to IP, mark suspicious.
    """
    reasons = []
    forms = re.findall(r'(?is)<form\b[^>]>(.?)</form>', html)
    if not forms:
        return reasons
    # find form action attributes
    actions = re.findall(r'(?is)<form\b[^>]*action=["\']?([^"\'>\s]+)', html)
    for act in actions:
        if act.strip() == '' or act.startswith('#') or act.lower().startswith('javascript:'):
            continue
        parsed = urlparse(act if re.match(r'^[a-zA-Z]+://', act) else 'http://' + act)
        domain = parsed.hostname or ''
        if domain and domain != base_domain and not domain.endswith(base_domain):
            reasons.append(f'form posts to external domain: {domain}')
        # if action is an IP
        if re.match(r'^\d+\.\d+\.\d+\.\d+$', domain):
            reasons.append(f'form posts to IP address: {domain}')
    return reasons

def analyze_scraped_content(content, base_domain):
    """
    Analyze scraped content for phishing indicators.
    """
    reasons = []
    if not content:
        return reasons

    # Check for suspicious keywords
    suspicious_keywords = ['login', 'password', 'account', 'secure', 'verify', 'update', 'billing', 'support', 'bank', 'credit card', 'paypal', 'amazon', 'google', 'facebook']
    for keyword in suspicious_keywords:
        if re.search(r'\b' + re.escape(keyword) + r'\b', content, re.IGNORECASE):
            reasons.append(f'Contains suspicious keyword: {keyword}')

    # Check for external links
    links = re.findall(r'href=["\']?([^"\'>\s]+)', content, re.IGNORECASE)
    for link in links:
        parsed = urlparse(link if re.match(r'^[a-zA-Z]+://', link) else 'http://' + link)
        domain = parsed.hostname or ''
        if domain and domain != base_domain and not domain.endswith(base_domain):
            reasons.append(f'Links to external domain: {domain}')

    # Check for obfuscated scripts or iframes
    if re.search(r'<iframe', content, re.IGNORECASE):
        reasons.append('Contains iframe elements -> potential for hidden content')
    if re.search(r'<script[^>]*src', content, re.IGNORECASE):
        reasons.append('Contains external scripts -> potential for malicious code')

    return reasons

# Advanced Heuristics Functions

def calculate_domain_entropy(domain):
    """
    Calculate Shannon entropy of the domain name.
    Higher entropy might indicate random or obfuscated domains.
    """
    if not domain:
        return 0
    entropy = 0
    length = len(domain)
    char_count = {}
    for char in domain:
        char_count[char] = char_count.get(char, 0) + 1
    for count in char_count.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy

def detect_suspicious_patterns(domain):
    """
    Detect suspicious patterns like excessive hyphens, numbers, or mixed cases.
    """
    reasons = []
    # Excessive hyphens
    if domain.count('-') > 2:
        reasons.append('Excessive hyphens in domain')
    # Excessive numbers
    num_count = sum(c.isdigit() for c in domain)
    if num_count > len(domain) * 0.3:
        reasons.append('High proportion of numbers in domain')
    # Mixed case (potential for obfuscation)
    if any(c.isupper() for c in domain) and any(c.islower() for c in domain):
        reasons.append('Mixed case in domain (potential obfuscation)')
    return reasons

def enhanced_keyword_analysis(domain, trusted_domains):
    """
    Enhanced analysis for suspicious keywords in domain.
    """
    reasons = []
    suspicious_keywords = ['login', 'secure', 'account', 'verify', 'update', 'billing', 'support', 'bank', 'credit', 'paypal', 'amazon', 'google', 'facebook', 'password', 'signin', 'webmail']
    domain_lower = domain.lower()
    for keyword in suspicious_keywords:
        if keyword in domain_lower:
            # Check if it's part of a trusted domain
            if not any(keyword in td.lower() for td in trusted_domains):
                reasons.append(f'Contains suspicious keyword: {keyword}')
    return reasons

# New Advanced Heuristics Functions

def domain_length_ratio(domain):
    """
    Calculate ratio of domain length to average length.
    Suspicious if too short or too long.
    """
    length = len(domain)
    avg_length = 12  # Approximate average domain length
    ratio = length / avg_length
    return ratio

def vowel_consonant_ratio(domain):
    """
    Calculate vowel to consonant ratio.
    Phishing domains might have unusual ratios.
    """
    vowels = 'aeiouAEIOU'
    consonants = 'bcdfghjklmnpqrstvwxyzBCDFGHJKLMNPQRSTVWXYZ'
    v_count = sum(1 for c in domain if c in vowels)
    c_count = sum(1 for c in domain if c in consonants)
    if c_count == 0:
        return 0
    return v_count / c_count

def subdomain_suspicion(subdomains, trusted_domains):
    """
    Check if subdomains contain suspicious patterns or mimic trusted domains.
    """
    reasons = []
    if not subdomains:
        return reasons
    for sub in subdomains:
        # Check for excessive length or numbers
        if len(sub) > 50 or sum(c.isdigit() for c in sub) > 5:
            reasons.append(f'Suspicious subdomain: {sub} (too long or many numbers)')
        # Check edit distance to trusted
        for td in trusted_domains:
            if levenshtein(sub, td) <= 2:
                reasons.append(f'Subdomain {sub} closely resembles trusted {td}')
    return reasons

def ssl_cert_age_days(cert):
    """
    Calculate age of SSL certificate in days.
    Very new certs might be suspicious.
    """
    if not cert:
        return None
    not_before = cert.get('notBefore')
    if not_before:
        try:
            nb = datetime.datetime.strptime(not_before, '%b %d %H:%M:%S %Y %Z')
            diff = datetime.datetime.utcnow() - nb
            return diff.days
        except ValueError:
            return None
    return None

def redirect_chain_length(url, max_redirects=10):
    """
    Check the length of redirect chain.
    Long chains might indicate obfuscation.
    """
    try:
        response = requests.get(url, timeout=10, allow_redirects=True, headers={'User-Agent':'Mozilla/5.0'})
        # Count redirects from history
        return len(response.history)
    except:
        return 0

# Machine Learning Model for Phishing Detection

# Load training data from file
def load_training_data():
    try:
        with open("training_data.json", "r") as f:
            return json.load(f)
    except FileNotFoundError:
        print("training_data.json not found, using default sample data.")
        return [
            {'domain': 'google.com', 'label': 0},
            {'domain': 'paypal-verify.com', 'label': 1},
        ]  # Minimal fallback

training_data = load_training_data()

def extract_features(domain, trusted_domains=None, subdomains=None, cert=None, url=None):
    """
    Extract features for ML model, now including more advanced ones.
    """
    if trusted_domains is None:
        trusted_domains = []
    if subdomains is None:
        subdomains = []
    features = {}
    features['length'] = len(domain)
    features['entropy'] = calculate_domain_entropy(domain)
    features['num_hyphens'] = domain.count('-')
    features['num_digits'] = sum(c.isdigit() for c in domain)
    features['has_punycode'] = 1 if is_punycode(domain) else 0
    features['has_non_ascii'] = 1 if has_non_ascii(domain) else 0
    features['suspicious_tld'] = 1 if suspicious_tld(domain) else 0
    features['is_shortener'] = 1 if is_url_shortener(domain) else 0
    # Levenshtein distance to closest trusted domain
    if trusted_domains:
        min_dist = min(levenshtein(domain, td) for td in trusted_domains)
        features['min_edit_dist'] = min_dist
    else:
        features['min_edit_dist'] = 0
    # Suspicious patterns count
    features['susp_patterns'] = len(detect_suspicious_patterns(domain))
    # Keyword count
    features['susp_keywords'] = len(enhanced_keyword_analysis(domain, trusted_domains))
    # New features
    features['length_ratio'] = domain_length_ratio(domain)
    features['vowel_cons_ratio'] = vowel_consonant_ratio(domain)
    features['subdomain_count'] = len(subdomains)
    features['subdomain_susp'] = len(subdomain_suspicion(subdomains, trusted_domains))
    features['cert_age_days'] = ssl_cert_age_days(cert) or 0
    features['redirect_chain_len'] = redirect_chain_length(url) if url else 0
    return features

def train_ml_model():
    """
    Train the ML model using loaded data.
    """
    df = pd.DataFrame(training_data)
    df['features'] = df['domain'].apply(lambda d: extract_features(d, ['google.com', 'amazon.com', 'facebook.com', 'paypal.com']))
    X = pd.DataFrame(list(df['features']))
    y = df['label']
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X_train, y_train)
    y_pred = model.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    print(f"ML Model Accuracy: {accuracy:.2f}")
    return model

# Global model variable (train once)
ml_model = train_ml_model()

def predict_phishing_ml(domain, trusted_domains=None, subdomains=None, cert=None, url=None):
    """
    Use ML model to predict if domain is phishing.
    Returns probability of being phishing.
    """
    features = extract_features(domain, trusted_domains, subdomains, cert, url)
    features_df = pd.DataFrame([features])
    prob = ml_model.predict_proba(features_df)[0][1]  # Probability of class 1 (phishing)
    return prob

def score_domain(target_url, trusted_domains=None):
    if trusted_domains is None:
        trusted_domains = []

    report = []
    score = 0  # higher -> more suspicious

    # Ensure URL has scheme
    if not re.match(r'^[a-zA-Z]+://', target_url):
        target_url = 'https://' + target_url

    domain = extract_domain(target_url)
    if not domain:
        raise ValueError("Couldn't parse domain from URL")

    report.append(f'Target domain: {domain}')

    # Basic checks: IDN / Punycode / non-ascii
    if is_punycode(domain):
        report.append('Uses Punycode (xn--): possible IDN/homoglyph trick')
        score += 25
    if has_non_ascii(domain):
        report.append('Contains non-ASCII characters: possible homoglyph / IDN attack')
        score += 20

    # suspicious TLDs
    if suspicious_tld(domain):
        report.append('Uses a TLD often associated with abuses (e.g., .tk /.ml /.ga)')
        score += 8

    # URL shortener check
    if is_url_shortener(domain):
        report.append('Domain is a known URL shortener -> suspicious')
        score += 15

    # Compare against trusted domains by edit distance
    if trusted_domains:
        best = None
        best_td = None
        for td in trusted_domains:
            d = levenshtein(domain, td)
            # also compare only the second-level + tld? keep simple
            if best is None or d < best:
                best = d
                best_td = td
        # heuristics:
        # small edit distance (1-3) to a trusted brand is suspicious
        if best is not None:
            report.append(f'Closest trusted domain: {best_td} (edit distance {best})')
            if best <= 2 and len(domain) <= 30:
                report.append('Small edit distance to trusted domain -> likely typosquat or fake')
                score += 30
            elif best <= 4:
                report.append('Moderate edit distance to trusted domain -> possibly suspicious')
                score += 12

    # repeated characters / long subdomain tricks (e.g., amazon.com.example.bad)
    parts = domain.split('.')
    if len(parts) >= 3:
        # if leftmost is like amazon.com appended as subdomain?
        left = '.'.join(parts[:-2])
        if any(td in left for td in trusted_domains):
            report.append('Trusted brand appears in subdomain (e.g., amazon.com.example.com) -> phishing pattern')
            score += 30

    # Check subdomains for fakes
    subdomains = get_subdomains(domain)
    if subdomains:
        report.append(f'Found {len(subdomains)} subdomains')
        fake_subs = []
        for sub in subdomains:
            if any(levenshtein(sub, td) <= 2 for td in trusted_domains):
                fake_subs.append(sub)
        if fake_subs:
            report.append(f'Potential fake subdomains: {fake_subs}')
            score += 20

    # Double letters / extra chars check (simple heuristic)
    if re.search(r'(.)\1\1', domain):  # triple repeated char
        report.append('Triple repeated character sequence in domain (e.g., "aaa")')
        score += 5

    # Advanced heuristics
    entropy = calculate_domain_entropy(domain)
    report.append(f'Domain entropy: {entropy:.2f}')
    if entropy > 4.0:  # Threshold for high entropy
        report.append('High domain entropy -> possible random/obfuscated domain')
        score += 10

    susp_patterns = detect_suspicious_patterns(domain)
    for pattern in susp_patterns:
        report.append(f'Suspicious pattern: {pattern}')
        score += 8

    enh_keywords = enhanced_keyword_analysis(domain, trusted_domains)
    for kw in enh_keywords:
        report.append(kw)
        score += 6

    # Get subdomains, cert, etc. for enhanced ML
    subdomains = get_subdomains(domain)
    cert = get_ssl_cert_info(domain)
    url_full = target_url

    # New heuristics
    len_ratio = domain_length_ratio(domain)
    if len_ratio < 0.5 or len_ratio > 2.0:
        report.append(f'Domain length ratio: {len_ratio:.2f} (unusual)')
        score += 5

    vc_ratio = vowel_consonant_ratio(domain)
    if vc_ratio < 0.2 or vc_ratio > 1.5:
        report.append(f'Vowel/consonant ratio: {vc_ratio:.2f} (unusual)')
        score += 3

    sub_susp = subdomain_suspicion(subdomains, trusted_domains)
    for s in sub_susp:
        report.append(s)
        score += 10

    cert_age = ssl_cert_age_days(cert)
    if cert_age is not None and cert_age < 30:
        report.append(f'SSL cert is very new: {cert_age} days')
        score += 15

    redir_len = redirect_chain_length(url_full)
    if redir_len > 3:
        report.append(f'Long redirect chain: {redir_len} redirects')
        score += 8

    # ML prediction with enhanced features
    ml_prob = predict_phishing_ml(domain, trusted_domains, subdomains, cert, url_full)
    report.append(f'ML phishing probability: {ml_prob:.2f}')
    if ml_prob > 0.5:
        report.append('ML model predicts phishing')
        score += int(ml_prob * 50)  # Add up to 50 points based on probability

    # Try network checks: resolve, get IP
    try:
        ips = get_ip_address(domain)
        if ips:
            report.append(f'Domain resolves to IPs: {ips}')
            for ip in ips:
                if re.match(r'^\d+\.\d+\.\d+\.\d+$', ip):
                    report.append(f'IP {ip} is a plain IP address -> suspicious for phishing')
                    score += 10
        else:
            report.append('Could not resolve domain to any IP')
            score += 5
    except Exception as e:
        report.append(f'Could not resolve domain: {e}')
        score += 5

    # Try fetching the page
    try:
        resp = requests.get(target_url, timeout=7, allow_redirects=True, headers={'User-Agent':'Mozilla/5.0 (PhishDetector)'})
        final_url = resp.url
        final_domain = urlparse(final_url).hostname or ''
        report.append(f'HTTP status: {resp.status_code}, final URL after redirects: {final_url}')
        if final_domain != domain:
            report.append(f'Redirects to a different domain: {final_domain}')
            score += 15
        # analyze HTML for forms
        html_issues = analyze_html_for_forms(resp.text, domain)
        for it in html_issues:
            report.append('HTML issue: ' + it)
            score += 12
        # check for login indicators but unexpected hostnames
        if re.search(r'(?i)(<input[^>]+type=["\']?password|login|sign in|signin)', resp.text):
            report.append('Page contains login/password fields or login keywords')
            score += 6
    except requests.exceptions.SSLError as e:
        report.append(f'SSL error when fetching: {e}')
        score += 12
    except Exception as e:
        report.append(f'Error fetching URL: {e}')
        score += 6

    # SSL certificate inspection (separate)
    try:
        cert = get_ssl_cert_info(domain)
        if cert:
            subj = cert.get('subject', ())
            issuer = cert.get('issuer', ())
            san = cert.get('subjectAltName', ())
            report.append(f'SSL cert subject: {subj}')
            report.append(f'SSL cert issuer: {issuer}')
            if san:
                san_domains = [entry[1] for entry in san if entry[0].lower() in ('dns','commonname')]
                report.append(f'SSL cert SAN: {san_domains}')
                # if none of SAN matches our domain, suspicious
                matches = any(domain.endswith(dn) or dn.endswith(domain) for dn in san_domains)
                if not matches and san_domains:
                    report.append('SSL cert SANs do not match domain -> suspicious')
                    score += 18
            # Check issuer for suspicious patterns (e.g., self-signed or unknown CA)
            issuer_str = str(issuer).lower()
            if 'self-signed' in issuer_str or 'unknown' in issuer_str or not issuer:
                report.append('SSL cert issuer is self-signed or unknown -> suspicious')
                score += 10
    except Exception as e:
        report.append(f'Error checking SSL cert: {e}')
        score += 5

    # WHOIS age check if available
    w_age = age_days_from_whois(domain)
    if w_age is not None:
        report.append(f'Domain age (days): {w_age}')
        if w_age < 90:
            report.append('Domain is very new (<90 days) -> suspicious for phishing campaigns')
            score += 20

    # final heuristic scoring -> verdict
    verdict = 'UNKNOWN'
    if score >= 60:
        verdict = 'HIGHLY SUSPICIOUS (likely phishing)'
    elif score >= 30:
        verdict = 'SUSPICIOUS'
    elif score >= 15:
        verdict = 'MILDLY SUSPICIOUS'
    else:
        verdict = 'LIKELY LEGITIMATE (but not guaranteed)'

    return {
        'domain': domain,
        'score': score,
        'verdict': verdict,
        'report': report
    }
