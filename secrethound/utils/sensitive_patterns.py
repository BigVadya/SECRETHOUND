import re
# Единый словарь паттернов для поиска чувствительных данных,
# упорядоченный по значимости информации для злоумышленника
PATTERNS = {
    # === 1. Критичные учётные данные и ключи доступа ===
    'Private Key PEM': re.compile(r"-----BEGIN\s+(?:RSA\s+)?PRIVATE KEY-----"),
    'AWS Access Key': re.compile(r'\bAKI[A-Z0-9]{16}\b'),
    'AWS Secret Key': re.compile(r'\b[0-9a-zA-Z]{40}\b'),
    'GitHub Personal Access Token': re.compile(r'\bghp_[0-9A-Za-z]{40}\b'),
    'Slack Bot Token': re.compile(r'\bxoxb-[0-9]{11}-[0-9]{11}-[0-9a-zA-Z]{24}\b'),
    'Firebase Secret': re.compile(r'\bAAAA[A-Za-z0-9_-]{120,}\b'),
    'Bearer/OAuth Token': re.compile(r"\b(?:Bearer|OAuth)\s+[A-Za-z0-9\-_]+\b", re.IGNORECASE),
    'JWT Token': re.compile(r"\beyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\b"),
    'Hardcoded API Key': re.compile(
        r'(?:api|apikey|key|secret|token|password)["\']?\s*[:=]\s*["\']?[A-Za-z0-9-_]{16,}["\']?',
        re.IGNORECASE
    ),
    'Sentry DSN': re.compile(r'https://[a-zA-Z0-9]+@[a-zA-Z0-9.-]+/\d+'),
    'Azure Storage Key': re.compile(r'\bEby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuQl4='),

    # === 2. Критичные сервисные пути ===
    'Admin Panel Path': re.compile(r'\b(?:/admin|/dashboard|/manager|/controlpanel)\b'),
    'Log File Path': re.compile(r'\b(?:/logs|/log|/error_log|/access_log)\b'),
    'Config File': re.compile(r'\b(?:\.env|\.env\.local|\.env\.production|\.env\.dev)\b'),
    'API Path': re.compile(r'/api/[A-Za-z0-9\-/_.?=&]+'),
    'Internal URL/IP': re.compile(
        r'(?:localhost|127\.0\.0\.1|10\.\d+\.\d+\.\d+|'
        r'192\.168\.\d+\.\d+|\.svc\.k8s\.|\.internal\.|'
        r'https?://[^/]+\.internal\.[^/\s]+)'
    ),

    # === 3. Учётные данные и сессии ===
    'Username/Login': re.compile(r"\b(?:логин|username)[\s:=]*\w+\b", re.IGNORECASE),
    'Password': re.compile(r"\b(?:пароль|password)[\s:=]*\S+\b", re.IGNORECASE),
    'Session ID': re.compile(r"\bsession[_-]?id=\w+\b", re.IGNORECASE),
    'MD5 Hash': re.compile(r"\b[A-Fa-f0-9]{32}\b"),
    'SHA-1 Hash': re.compile(r"\b[A-Fa-f0-9]{40}\b"),
    'SHA-256 Hash': re.compile(r"\b[A-Fa-f0-9]{64}\b"),
    'Public SSH Key': re.compile(r"ssh-rsa\s+[A-Za-z0-9+/=]{100,}"),
    'Certificate PEM': re.compile(r"-----BEGIN\s+CERTIFICATE-----"),
    'XSRF Token': re.compile(r'\bXSRF-TOKEN=[A-Za-z0-9\-_]+\b'),
    'JWT Cookie': re.compile(r'\b(jwt|auth_token)=ey[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\b'),

    # === 4. Финансовые данные ===
    'Credit Card Visa/MC': re.compile(r"(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14})"),
    'Credit Card Amex': re.compile(r"3[47][0-9]{13}"),
    'CVV/CVC 3 digits': re.compile(r"\b(?:CVV2?|CVC)[\s:=]*\d{3}\b", re.IGNORECASE),
    'IBAN': re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{4}(?:\s?[A-Z0-9]{4}){2,}\b"),
    'SWIFT/BIC INT': re.compile(r"\bSWIFT[\s:=]?[A-Z]{6}[A-Z0-9]{2}(?:[A-Z0-9]{3})?\b"),
    'Bank Account RU': re.compile(r"\b\d{20}\b"),
    'Routing Number US': re.compile(r"\b\d{9}\b"),
    'BIC': re.compile(r"БИК[\s:=]?\d{9}", re.IGNORECASE),
    'Corr Account RU': re.compile(r"корр[\.? ]?счет[\s:=]?\d{20}", re.IGNORECASE),
    'Bitcoin Address': re.compile(r'\b(bc1|[13][a-zA-HJ-NP-Z0-9]{25,39})\b'),
    'PayPal Transaction ID': re.compile(r'\b(?:PP-|PAY-)[A-Z0-9]{8,12}\b'),

    # === 5. Персональные идентификаторы (PII) ===
    'Passport (RU)': re.compile(r"паспорт\s*(?:серия\s*)?\d{2}[\s-]?\d{2}[\s-]?\d{6}", re.IGNORECASE),
    'Passport (EN)': re.compile(r"Passport\s*(?:No\.?|number)?\s*\d{6,9}", re.IGNORECASE),
    'SNILS': re.compile(r"\b\d{3}-\d{3}-\d{3}\s*\d{2}\b"),
    'INN (10 or 12 digits)': re.compile(r"\b\d{10}\b|\b\d{12}\b"),
    'Driver License (RU)': re.compile(r"\bВУ\s*\d{2}\s*\d{2}\s*\d{6}\b", re.IGNORECASE),
    'Driver License (EN)': re.compile(r"\bDriver(?:'s)?\s+License\s*[A-Z0-9\-]{5,15}\b", re.IGNORECASE),
    'Social Security Number (SSN)': re.compile(r'\b\d{3}-\d{2}-\d{4}\b'),
    'Medical Record Number': re.compile(r'\bMRN\d{8}\b'),
    'Insurance Policy Number': re.compile(r'\bINS\d{10,15}\b'),

    # === 6. Контактная информация ===
    'Email Address':        re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),

    'Personal Email': re.compile(
        r'\b[A-Za-z0-9._%+-]+@(?:gmail|yahoo|hotmail|outlook|mail|yandex|protonmail|icloud|aol|zoho|mailru|ya|bk|list|inbox|rambler|ukr)\.(?:com|ru|net|org|info|co|ua|kz|by|me|in|fr|de|es|it|nl|pl|se|no|dk|fi|jp|cn|hk|sg|au|ca|mx|br|ar|cl|pe|co|ve|in|pk|bd|np|lk|ph|my|th|vn|kr|sa|ae|qa|om|kw|eg|ma|dz|tn|ng|ke|za|gh|ci|sn|cm|ga|cd|cg|ao|mz|tz|ug|et|sd|so|dj|er|rw|bi|mg|mu|re|sc|km|mv|fm|pw|mh|tv|ki|to|ws|fj|sb|vu|nc|pf|ck|nu|tk|wf|ht|cu|jm|bb|bs|ag|gd|lc|vc|ms|pr|vi|ai|bm|ky|vg|tc|mp|gu|as|um|ac|ad|ae|af|ag|ai|al|am|an|ao|aq|ar|as|at|au|aw|ax|az|ba|bb|bd|be|bf|bg|bh|bi|bj|bl|bm|bn|bo|bq|br|bs|bt|bv|bw|by|bz|ca|cc|cd|cf|cg|ch|ci|ck|cl|cm|cn|co|cr|cu|cv|cw|cx|cy|cz|de|dj|dk|dm|do|dz|ec|ee|eg|eh|er|es|et|eu|fi|fj|fk|fm|fo|fr|ga|gb|gd|ge|gf|gg|gh|gi|gl|gm|gn|gp|gq|gr|gs|gt|gu|gw|gy|hk|hm|hn|hr|ht|hu|id|ie|il|im|in|io|iq|ir|is|it|je|jm|jo|jp|ke|kg|kh|ki|km|kn|kp|kr|kw|ky|kz|la|lb|lc|li|lk|lr|ls|lt|lu|lv|ly|ma|mc|md|me|mf|mg|mh|mk|ml|mm|mn|mo|mp|mq|mr|ms|mt|mu|mv|mw|mx|my|mz|na|nc|ne|nf|ng|ni|nl|no|np|nr|nu|nz|om|pa|pe|pf|pg|ph|pk|pl|pm|pn|pr|ps|pt|pw|py|qa|re|ro|rs|ru|rw|sa|sb|sc|sd|se|sg|sh|si|sj|sk|sl|sm|sn|so|sr|ss|st|su|sv|sx|sy|sz|tc|td|tf|tg|th|tj|tk|tl|tm|tn|to|tp|tr|tt|tv|tw|tz|ua|ug|uk|um|us|uy|uz|va|vc|ve|vg|vi|vn|vu|wf|ws|ye|yt|za|zm|zw)\b',
        re.IGNORECASE
    ),
    'Phone Number':         re.compile(r"\+?(\d{1,3}[\s\-\.]?)?\(?\d{3,4}\)?[\s\-\.]?\d{3}[\s\-\.]?\d{2,4}[\s\-\.]?\d{2,4}"),
    'GPS Coordinates': re.compile(r"\b[-+]?\d{1,3}\.\d+,\s*[-+]?\d{1,3}\.\d+\b"),
    'IP Address': re.compile(r"\bIP[\s:=]?\d{1,3}(?:\.\d{1,3}){3}\b", re.IGNORECASE),
    'Physical Address': re.compile(r'\b\d+\s+([A-Za-z]+\.?|\b[A-Z][a-z]+\b)\s+(?:St\.|Ave\.|Blvd\.|Road|Lane|Way|Drive|Court|Terrace|Circle|Place|Plaza|Square|Trail|Parkway|Commons|Highway|Expressway)\b'),
    'Fax Number': re.compile(r'\b(?:Fax|FAX|факс)[\s:=]?\+?(\d{1,3}[\s\-\.]?)?\(?\d{3,4}\)?[\s\-\.]?\d{3}[\s\-\.]?\d{2,4}[\s\-\.]?\d{2,4}\b'),

    # === 7. Юридическая и коммерческая информация ===
    'Confidential Tag': re.compile(r"\b(?:Конфиденциально|Confidential|INTERNAL_USE_ONLY|RESTRICTED|TOP_SECRET)\b", re.IGNORECASE),
    'Contract Number': re.compile(r"\b(?:Договор|Contract)\s+№\s*\d+\b", re.IGNORECASE),
    'NDA Agreement': re.compile(r'\b(?:NDA|Non-Disclosure\s+Agreement)\b', re.IGNORECASE),
    'Legal Correspondence': re.compile(r"\b(?:Уважаемый|Dear)\b", re.IGNORECASE),
    'Financial Model': re.compile(r"\b(?:финансовая\s+модель|financial\s+model)\b", re.IGNORECASE),
    'Company Confidential': re.compile(r'\b(?:Коммерческая тайна|Trade Secret|Company Proprietary)\b', re.IGNORECASE),

    # === 8. Прочие чувствительные данные ===
    'Birth Date': re.compile(r"\b\d{1,2}[\/.\-]\d{1,2}[\/.\-]\d{2,4}\b"),
    'Department': re.compile(r"\b(department|отдел|служба|unit|division)\b", re.IGNORECASE),
    'Job Title': re.compile(
        r'\b(?:senior|junior)\s+(?:software|devops|qa|product)?\s*(?:engineer|developer|manager|architect|analyst|consultant|specialist|lead|director|executive|officer)\b',
        re.IGNORECASE
    ),
    'File/Doc Links': re.compile(r"https?://[^\s]+\.(pdf|docx?|xlsx?|csv|pptx?|txt)", re.IGNORECASE),
    'File Reference': re.compile(r"\b[\w._-]+\.(pdf|docx?|xlsx?|csv|xls|pptx?|txt)\b", re.IGNORECASE),
    'Car Plate Number': re.compile(r'\b[A-Z]{2}\d{3}[A-Z]{2}\d{2,3}\b'),
    'One-Time Code': re.compile(r'\b\d{6}\b'),
    'Credit Report ID': re.compile(r'\bCRN\d{8}\b'),
    'Crypto Wallet Address': re.compile(r'\b0x[a-fA-F0-9]{40}\b'),
    'Database Connection String': re.compile(r'\b(?:mongodb|mysql|postgresql|redis):\/\/[^\s]+\b'),
    'OAuth2 Refresh Token': re.compile(r'\brefresh_token=[A-Za-z0-9\-_]+\b'),
    'Internal Project ID': re.compile(r'\b(project_id|internal_key|internal_token)=\w+\b')
}