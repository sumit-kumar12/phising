
import argparse
import json

def main():
    parser = argparse.ArgumentParser(description="Phishing and Malicious URL Detector")
    parser.add_argument("--url", required=True, help="The domain or URL to analyze.")
    parser.add_argument("--trusted", help="Comma-separated list of trusted domains (e.g., amazon.com,google.com).")
    args = parser.parse_args()

    # Load API keys from api.json
    try:
        with open("api.json", "r") as f:
            api_config = json.load(f)
    except FileNotFoundError:
        print("Error: api.json not found.")
        return
    except json.JSONDecodeError:
        print("Error: Invalid api.json format.")
        return

    scraperapi_key = api_config.get("scraperapi", {}).get("api_key") if api_config.get("scraperapi", {}).get("enabled", False) else None
    abuseipdb_key = api_config.get("abuseipdb", {}).get("api_key") if api_config.get("abuseipdb", {}).get("enabled", False) else None
    google_api_key = api_config.get("google", {}).get("api_key") if api_config.get("google", {}).get("enabled", False) else None
    google_cse_id = api_config.get("google", {}).get("cse_id") if api_config.get("google", {}).get("enabled", False) else None
    whois_key = api_config.get("whois", {}).get("api_key") if api_config.get("whois", {}).get("enabled", False) else None

    trusted_domains = args.trusted.split(',') if args.trusted else ['amazon.com', 'google.com', 'facebook.com', 'paypal.com']

    print(f"Analyzing {args.url}...")

    from src.utils import get_subdomains, get_whois_info, get_ip_address, get_abuseipdb_info, google_search, scrape_with_scraperapi, score_domain

    results = {}

    # Run scoring
    score_result = score_domain(args.url, trusted_domains)
    print("\n=== Phish Detector Report ===")
    print(f"Domain: {score_result['domain']}")
    print(f"Score: {score_result['score']}")
    print(f"Verdict: {score_result['verdict']}\n")
    print("Details:")
    for r in score_result['report']:
        print(' -', r)
    results["score"] = score_result

    subdomains = get_subdomains(args.url)
    if subdomains:
        print("\n[+] Subdomains found:")
        for subdomain in subdomains:
            print(f"    - {subdomain}")
        results["subdomains"] = subdomains

    whois_info = get_whois_info(args.url, whois_key)
    if whois_info:
        print("\n[+] Whois information:")
        for key, value in whois_info.items():
            print(f"    - {key}: {value}")
        results["whois"] = whois_info

    ip_addresses = get_ip_address(args.url)
    if ip_addresses:
        print(f"\n[+] IP addresses: {ip_addresses}")
        results["ip_addresses"] = ip_addresses

        if abuseipdb_key:
            for ip in ip_addresses:
                abuseipdb_info = get_abuseipdb_info(ip, abuseipdb_key)
                if abuseipdb_info:
                    print(f"\n[+] AbuseIPDB information for {ip}:")
                    for key, value in abuseipdb_info.items():
                        print(f"    - {key}: {value}")
                    results[f"abuseipdb_{ip}"] = abuseipdb_info

    if google_api_key and google_cse_id:
        google_results = google_search(args.url, google_api_key, google_cse_id)
        if google_results:
            print("\n[+] Google search results:")
            for result in google_results:
                print(f"    - {result['title']}: {result['link']}")
            results["google_search"] = google_results

    if scraperapi_key:
        scraped_content = scrape_with_scraperapi(args.url, scraperapi_key)
        if scraped_content:
            print("\n[+] Scraped page content:")
            print(scraped_content)
            results["scraped_content"] = scraped_content

            # Analyze scraped content
            from src.utils import analyze_scraped_content
            scraped_analysis = analyze_scraped_content(scraped_content, args.url)
            if scraped_analysis:
                print("\n[+] Scraped content analysis:")
                for issue in scraped_analysis:
                    print(f"    - {issue}")
                results["scraped_analysis"] = scraped_analysis

    from src.utils import save_to_json, save_to_pdf

    save_to_json(results, f"results/{args.url.replace('/', '_')}.json")
    save_to_pdf(results, f"results/{args.url.replace('/', '_')}.pdf")

    print("\n[+] Results saved to results/ folder.")

if __name__ == "__main__":
    main()
