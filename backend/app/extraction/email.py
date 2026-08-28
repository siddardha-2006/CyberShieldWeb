import re
from typing import Dict, Any, List, Optional
from urlextract import URLExtract
import tldextract


class EmailExtractor:
    url_extractor = URLExtract()

    @classmethod
    def extract_from_raw_text(cls, raw_email: str) -> Dict[str, Any]:
        """
        Parses full raw pasted email text, extracting Sender (From), Display Name,
        Reply-To, Subject, Date, and Body using heuristic and NLP tokenization.
        """
        text = raw_email.strip()
        lines = text.splitlines()
        
        sender = ""
        display_name = ""
        reply_to = ""
        subject = ""
        body_lines = []
        in_body = False
        headers: Dict[str, str] = {}

        # Regex patterns for common email header lines (multi-client / multilingual)
        from_pattern = re.compile(r'^(?:From|Sender|De|Von|De\s*la\s*part\s*de):\s*(.+)$', re.IGNORECASE)
        reply_to_pattern = re.compile(r'^(?:Reply-To|Répondre\s*à|Antwort-an):\s*(.+)$', re.IGNORECASE)
        subject_pattern = re.compile(r'^(?:Subject|Objet|Betreff|Asunto|विषय):\s*(.+)$', re.IGNORECASE)
        to_pattern = re.compile(r'^(?:To|Destinataire|An|Para):\s*(.+)$', re.IGNORECASE)
        date_pattern = re.compile(r'^(?:Date|Datum|Fecha):\s*(.+)$', re.IGNORECASE)

        header_boundary_passed = False

        for line in lines:
            trimmed = line.strip()
            
            # If empty line after headers, marks start of body
            if not trimmed and (sender or subject or headers) and not header_boundary_passed:
                header_boundary_passed = True
                continue

            if not header_boundary_passed:
                from_match = from_pattern.match(trimmed)
                if from_match:
                    raw_from = from_match.group(1).strip()
                    # Check for "Name <email@domain.com>" or "email@domain.com"
                    email_in_angle = re.search(r'<([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})>', raw_from)
                    if email_in_angle:
                        sender = email_in_angle.group(1)
                        display_name = re.sub(r'<[^>]+>', '', raw_from).strip().strip('"\'')
                    else:
                        # Direct email or name
                        plain_email = re.search(r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b', raw_from)
                        if plain_email:
                            sender = plain_email.group(0)
                            display_name = raw_from.replace(sender, '').strip().strip('"\'')
                        else:
                            display_name = raw_from
                    headers["from"] = raw_from
                    continue

                reply_match = reply_to_pattern.match(trimmed)
                if reply_match:
                    raw_rt = reply_match.group(1).strip()
                    rt_email = re.search(r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b', raw_rt)
                    if rt_email:
                        reply_to = rt_email.group(0)
                    headers["reply-to"] = raw_rt
                    continue

                subj_match = subject_pattern.match(trimmed)
                if subj_match:
                    subject = subj_match.group(1).strip()
                    headers["subject"] = subject
                    continue

                to_match = to_pattern.match(trimmed)
                if to_match:
                    headers["to"] = to_match.group(1).strip()
                    continue

                date_match = date_pattern.match(trimmed)
                if date_match:
                    headers["date"] = date_match.group(1).strip()
                    continue

            # Accumulate body text
            body_lines.append(line)

        body = "\n".join(body_lines).strip()

        # Fallback: if no From header was explicitly found, search body for candidate sender
        if not sender:
            found_emails = re.findall(r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b', text)
            if found_emails:
                sender = found_emails[0]
            else:
                sender = "unknown-sender@unverified.org"

        # Fallback: if no Subject header was found, use the first non-empty line as subject
        if not subject and body_lines:
            first_non_empty = next((l.strip() for l in body_lines if l.strip()), "No Subject Provided")
            subject = first_non_empty[:80]

        # Use full extract pipeline
        return cls.extract(
            sender=sender,
            subject=subject,
            body=body or text,
            reply_to=reply_to or None,
            headers=headers,
            display_name=display_name
        )

    @classmethod
    def extract(
        cls, 
        sender: str, 
        subject: str, 
        body: str, 
        reply_to: Optional[str] = None, 
        headers: Optional[Dict[str, str]] = None,
        display_name: Optional[str] = None
    ) -> Dict[str, Any]:
        headers = headers or {}
        display_name = display_name or ""
        
        # Parse domains for sender & reply_to
        sender_ext = tldextract.extract(sender)
        sender_domain = sender_ext.registered_domain
        
        reply_to_domain = ""
        is_mismatched_reply_to = False
        if reply_to:
            rt_ext = tldextract.extract(reply_to)
            reply_to_domain = rt_ext.registered_domain
            if sender_domain and reply_to_domain and sender_domain != reply_to_domain:
                is_mismatched_reply_to = True

        # Check for display name spoofing
        # E.g. Display name says "PayPal Support" or "CEO" or "Microsoft", but sender domain is "attacker.xyz"
        display_name_spoofed = False
        if display_name:
            lower_dn = display_name.lower()
            impersonation_brands = ["microsoft", "apple", "paypal", "netflix", "chase", "bank", "security", "ceo", "director", "payroll"]
            for b in impersonation_brands:
                if b in lower_dn and sender_domain and b not in sender_domain:
                    display_name_spoofed = True
                    break

        # Extract links from subject & body
        combined_text = f"{subject}\n{body}"
        try:
            urls = cls.url_extractor.find_urls(combined_text)
        except Exception:
            urls = []
            
        # Regex fallback for backticks, markdown links, or custom TLDs
        raw_urls = re.findall(r'https?://[^\s`"\'<>]+', combined_text)
        for ru in raw_urls:
            cleaned_u = ru.strip('`"\'.,;()')
            if cleaned_u and cleaned_u not in urls:
                urls.append(cleaned_u)

        domains = []
        for u in urls:
            try:
                ext = tldextract.extract(u)
                if ext.registered_domain:
                    domains.append(ext.registered_domain)
                elif ext.domain:
                    domains.append(f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain)
            except Exception:
                pass

        # Check for spoofing signals in headers
        spf_pass = "pass" in str(headers.get("received-spf", "")).lower() or "pass" in str(headers.get("authentication-results", "")).lower()
        dkim_pass = "dkim=pass" in str(headers.get("authentication-results", "")).lower()
        dmarc_pass = "dmarc=pass" in str(headers.get("authentication-results", "")).lower()
        
        return {
            "sender": sender,
            "display_name": display_name,
            "sender_domain": sender_domain,
            "reply_to": reply_to,
            "reply_to_domain": reply_to_domain,
            "is_mismatched_reply_to": is_mismatched_reply_to,
            "display_name_spoofed": display_name_spoofed,
            "subject": subject,
            "body_snippet": body[:500],
            "urls": urls,
            "domains": list(set(domains)),
            "headers": headers,
            "auth_signals": {
                "spf_pass": spf_pass,
                "dkim_pass": dkim_pass,
                "dmarc_pass": dmarc_pass,
                "has_spoof_mismatch": is_mismatched_reply_to,
                "display_name_spoofed": display_name_spoofed
            }
        }
