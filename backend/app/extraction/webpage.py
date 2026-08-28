from typing import Dict, Any, List, Optional
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import tldextract


class WebpageExtractor:
    @classmethod
    def extract_static(cls, html_content: str, base_url: str = "") -> Dict[str, Any]:
        soup = BeautifulSoup(html_content, "html.parser")
        
        # Forms analysis
        forms = []
        for form in soup.find_all("form"):
            action = form.get("action", "")
            method = form.get("method", "get").lower()
            inputs = form.find_all("input")
            input_types = [inp.get("type", "text").lower() for inp in inputs]
            input_names = [inp.get("name", "") for inp in inputs]
            
            has_password = "password" in input_types
            has_otp = any("otp" in str(n).lower() or "code" in str(n).lower() for n in input_names)
            has_card = any("card" in str(n).lower() or "cvv" in str(n).lower() for n in input_names)
            
            full_action = urljoin(base_url, action) if base_url else action
            forms.append({
                "action": full_action,
                "method": method,
                "has_password": has_password,
                "has_otp": has_otp,
                "has_card": has_card,
                "input_count": len(inputs)
            })
            
        # Links
        links = []
        for a in soup.find_all("a", href=True):
            href = a['href']
            if href.startswith("http") or href.startswith("//"):
                links.append(href)
            elif base_url:
                links.append(urljoin(base_url, href))
                
        # Scripts
        scripts = []
        for script in soup.find_all("script"):
            src = script.get("src")
            if src:
                scripts.append(urljoin(base_url, src) if base_url else src)
                
        # Title & Meta
        title = soup.title.string.strip() if soup.title and soup.title.string else ""
        text_content = ' '.join(soup.stripped_strings)
        
        return {
            "title": title,
            "text_sample": text_content[:1000],
            "total_forms": len(forms),
            "forms": forms,
            "external_links_count": len(links),
            "external_links": links[:20],
            "scripts_count": len(scripts),
            "scripts": scripts[:20],
            "has_login_form": any(f.get("has_password") for f in forms),
            "has_payment_form": any(f.get("has_card") for f in forms),
            "has_otp_form": any(f.get("has_otp") for f in forms)
        }

