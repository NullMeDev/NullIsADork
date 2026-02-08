"""
Captcha Solver Module — Multi-provider async captcha solving

Supports 3 providers with automatic fallback chain:
  1. 2captcha  (2captcha-python / AsyncTwoCaptcha)
  2. NopeCHA   (nopecha / AsyncHTTPXAPIClient or aiohttp)
  3. Anti-Captcha (anticaptchaofficial)

Captcha types handled:
  reCAPTCHA v2/v3, hCaptcha, Cloudflare Turnstile,
  FunCaptcha, DataDome, GeeTest v3/v4, image captcha

Integration points:
  - engines.py: solve captchas blocking search engine results
  - main_v3.py: solve captchas on target sites during /scan
  - waf_detector.py: provides captcha type detection
"""

import re
import asyncio
import time
from typing import Optional, Dict, List, Any, Tuple
from dataclasses import dataclass, field
from loguru import logger


# ────────────────────────── CAPTCHA TYPES ──────────────────────────

class CaptchaType:
    RECAPTCHA_V2 = "recaptcha_v2"
    RECAPTCHA_V3 = "recaptcha_v3"
    HCAPTCHA = "hcaptcha"
    TURNSTILE = "turnstile"
    FUNCAPTCHA = "funcaptcha"
    DATADOME = "datadome"
    GEETEST_V3 = "geetest_v3"
    GEETEST_V4 = "geetest_v4"
    IMAGE = "image"
    TEXT = "text"


# ────────────────────────── SITEKEY EXTRACTOR ──────────────────────────

class SitekeyExtractor:
    """Extract captcha sitekeys and metadata from HTML content."""

    # reCAPTCHA patterns
    _RECAPTCHA_SITEKEY = [
        re.compile(r'data-sitekey=["\']([A-Za-z0-9_-]{40})["\']', re.I),
        re.compile(r'grecaptcha\.execute\(["\']([A-Za-z0-9_-]{40})["\']', re.I),
        re.compile(r'recaptcha/api\.js\?.*?render=([A-Za-z0-9_-]{40})', re.I),
        re.compile(r'recaptcha/enterprise\.js\?.*?render=([A-Za-z0-9_-]{40})', re.I),
        re.compile(r'sitekey\s*[:=]\s*["\']([A-Za-z0-9_-]{40})["\']', re.I),
    ]

    # hCaptcha patterns
    _HCAPTCHA_SITEKEY = [
        re.compile(r'class=["\'][^"\']*h-captcha[^"\']*["\'][^>]*data-sitekey=["\']([a-f0-9-]{36})["\']', re.I),
        re.compile(r'data-sitekey=["\']([a-f0-9-]{36})["\'][^>]*class=["\'][^"\']*h-captcha', re.I),
        re.compile(r'data-sitekey=["\']([a-f0-9-]{36,50})["\']', re.I),
        re.compile(r'hcaptcha\.com/1/api\.js\?.*?sitekey=([a-f0-9-]{36})', re.I),
    ]

    # Turnstile patterns
    _TURNSTILE_SITEKEY = [
        re.compile(r'class=["\'][^"\']*cf-turnstile[^"\']*["\'][^>]*data-sitekey=["\']([A-Za-z0-9_-]{20,65})["\']', re.I),
        re.compile(r'data-sitekey=["\']([A-Za-z0-9_-]{20,65})["\'][^>]*class=["\'][^"\']*cf-turnstile', re.I),
        re.compile(r'turnstile\.render\([^)]*sitekey\s*:\s*["\']([A-Za-z0-9_-]{20,65})["\']', re.I),
    ]

    # FunCaptcha patterns
    _FUNCAPTCHA_KEY = [
        re.compile(r'data-pkey=["\']([A-Za-z0-9-]{30,50})["\']', re.I),
        re.compile(r'arkoselabs\.com/v2/([A-Za-z0-9-]{30,50})/', re.I),
        re.compile(r'funcaptcha\.com/fc/api/\?pkey=([A-Za-z0-9-]{30,50})', re.I),
    ]

    # GeeTest patterns
    _GEETEST_GT = [
        re.compile(r'gt\s*[:=]\s*["\']([a-f0-9]{32})["\']', re.I),
    ]
    _GEETEST_CHALLENGE = [
        re.compile(r'challenge\s*[:=]\s*["\']([a-f0-9]{32,})["\']', re.I),
    ]

    # DataDome patterns
    _DATADOME_URL = [
        re.compile(r'(https://geo\.captcha-delivery\.com/captcha/\?[^"\'>\s]+)', re.I),
    ]

    # Generic captcha detection (for pages where we can't extract sitekey)
    _CAPTCHA_INDICATORS = {
        CaptchaType.RECAPTCHA_V2: [
            re.compile(r'google\.com/recaptcha', re.I),
            re.compile(r'g-recaptcha', re.I),
            re.compile(r'grecaptcha', re.I),
            re.compile(r'recaptcha\.js', re.I),
        ],
        CaptchaType.RECAPTCHA_V3: [
            re.compile(r'recaptcha/api\.js\?.*?render=', re.I),
            re.compile(r'grecaptcha\.execute', re.I),
            re.compile(r'recaptcha/enterprise', re.I),
        ],
        CaptchaType.HCAPTCHA: [
            re.compile(r'hcaptcha\.com', re.I),
            re.compile(r'h-captcha', re.I),
        ],
        CaptchaType.TURNSTILE: [
            re.compile(r'challenges\.cloudflare\.com/turnstile', re.I),
            re.compile(r'cf-turnstile', re.I),
        ],
        CaptchaType.FUNCAPTCHA: [
            re.compile(r'funcaptcha', re.I),
            re.compile(r'arkoselabs', re.I),
        ],
        CaptchaType.DATADOME: [
            re.compile(r'captcha-delivery\.com', re.I),
            re.compile(r'datadome', re.I),
        ],
        CaptchaType.GEETEST_V3: [
            re.compile(r'geetest\.com', re.I),
            re.compile(r'gt\.js', re.I),
        ],
    }

    @classmethod
    def detect(cls, html: str) -> Optional[Dict[str, Any]]:
        """Detect captcha type and extract sitekey from HTML.
        
        Returns dict with: type, sitekey, and any extra params.
        Returns None if no captcha detected.
        """
        if not html:
            return None

        # Check for reCAPTCHA v3 first (subset of v2 patterns)
        for pat in cls._RECAPTCHA_SITEKEY:
            m = pat.search(html)
            if m:
                sitekey = m.group(1)
                # Determine v2 vs v3
                is_v3 = any(p.search(html) for p in cls._CAPTCHA_INDICATORS[CaptchaType.RECAPTCHA_V3])
                return {
                    "type": CaptchaType.RECAPTCHA_V3 if is_v3 else CaptchaType.RECAPTCHA_V2,
                    "sitekey": sitekey,
                }

        # hCaptcha
        for pat in cls._HCAPTCHA_SITEKEY:
            m = pat.search(html)
            if m:
                sitekey = m.group(1)
                # UUID format = hCaptcha, otherwise might be reCAPTCHA
                if len(sitekey) >= 36 and '-' in sitekey:
                    return {"type": CaptchaType.HCAPTCHA, "sitekey": sitekey}

        # Turnstile
        for pat in cls._TURNSTILE_SITEKEY:
            m = pat.search(html)
            if m:
                return {"type": CaptchaType.TURNSTILE, "sitekey": m.group(1)}

        # FunCaptcha
        for pat in cls._FUNCAPTCHA_KEY:
            m = pat.search(html)
            if m:
                return {"type": CaptchaType.FUNCAPTCHA, "sitekey": m.group(1)}

        # DataDome
        for pat in cls._DATADOME_URL:
            m = pat.search(html)
            if m:
                return {"type": CaptchaType.DATADOME, "captcha_url": m.group(1)}

        # GeeTest
        gt_match = None
        for pat in cls._GEETEST_GT:
            m = pat.search(html)
            if m:
                gt_match = m.group(1)
                break
        if gt_match:
            challenge = None
            for pat in cls._GEETEST_CHALLENGE:
                m = pat.search(html)
                if m:
                    challenge = m.group(1)
                    break
            # v4 has captcha_id but no challenge in the same way
            is_v4 = "geetest_v4" in html.lower() or "captcha_id" in html.lower()
            return {
                "type": CaptchaType.GEETEST_V4 if is_v4 else CaptchaType.GEETEST_V3,
                "gt": gt_match,
                "challenge": challenge,
            }

        # Generic detection (no sitekey, but captcha presence known)
        for ctype, patterns in cls._CAPTCHA_INDICATORS.items():
            for pat in patterns:
                if pat.search(html[:5000]):
                    return {"type": ctype, "sitekey": None}

        return None

    @classmethod
    def detect_type_from_name(cls, name: str) -> Optional[str]:
        """Map WAF detector bot_protection name to CaptchaType."""
        mapping = {
            "reCAPTCHA": CaptchaType.RECAPTCHA_V2,
            "hCaptcha": CaptchaType.HCAPTCHA,
            "Turnstile": CaptchaType.TURNSTILE,
            "FunCaptcha": CaptchaType.FUNCAPTCHA,
            "DataDome": CaptchaType.DATADOME,
            "GeeTest": CaptchaType.GEETEST_V3,
        }
        return mapping.get(name)


# ────────────────────────── SOLVE RESULT ──────────────────────────

@dataclass
class SolveResult:
    """Result from a captcha solve attempt."""
    success: bool
    token: Optional[str] = None
    provider: Optional[str] = None
    captcha_type: Optional[str] = None
    solve_time: float = 0.0
    cost: float = 0.0
    error: Optional[str] = None


# ────────────────────────── SOLVER STATS ──────────────────────────

@dataclass
class SolverStats:
    """Track captcha solving statistics."""
    total_attempts: int = 0
    total_solved: int = 0
    total_failed: int = 0
    total_cost: float = 0.0
    total_time: float = 0.0
    by_type: Dict[str, Dict[str, int]] = field(default_factory=dict)
    by_provider: Dict[str, Dict[str, int]] = field(default_factory=dict)

    def record(self, result: SolveResult):
        self.total_attempts += 1
        if result.success:
            self.total_solved += 1
        else:
            self.total_failed += 1
        self.total_cost += result.cost
        self.total_time += result.solve_time

        # Per-type stats
        ctype = result.captcha_type or "unknown"
        if ctype not in self.by_type:
            self.by_type[ctype] = {"solved": 0, "failed": 0}
        self.by_type[ctype]["solved" if result.success else "failed"] += 1

        # Per-provider stats
        provider = result.provider or "unknown"
        if provider not in self.by_provider:
            self.by_provider[provider] = {"solved": 0, "failed": 0}
        self.by_provider[provider]["solved" if result.success else "failed"] += 1


# ────────────────────────── PROVIDER BASE ──────────────────────────

class CaptchaProvider:
    """Base class for captcha solving providers."""
    name: str = "base"

    async def solve_recaptcha_v2(self, sitekey: str, url: str, **kw) -> Optional[str]:
        return None

    async def solve_recaptcha_v3(self, sitekey: str, url: str, **kw) -> Optional[str]:
        return None

    async def solve_hcaptcha(self, sitekey: str, url: str, **kw) -> Optional[str]:
        return None

    async def solve_turnstile(self, sitekey: str, url: str, **kw) -> Optional[str]:
        return None

    async def solve_funcaptcha(self, sitekey: str, url: str, **kw) -> Optional[str]:
        return None

    async def solve_datadome(self, captcha_url: str, page_url: str, **kw) -> Optional[str]:
        return None

    async def solve_geetest_v3(self, gt: str, challenge: str, url: str, **kw) -> Optional[str]:
        return None

    async def solve_geetest_v4(self, captcha_id: str, url: str, **kw) -> Optional[str]:
        return None

    async def solve_image(self, image_path_or_base64: str, **kw) -> Optional[str]:
        return None

    async def get_balance(self) -> float:
        return 0.0


# ────────────────────────── 2CAPTCHA PROVIDER ──────────────────────────

class TwoCaptchaProvider(CaptchaProvider):
    """2captcha.com provider using AsyncTwoCaptcha."""
    name = "2captcha"

    def __init__(self, api_key: str, timeout: int = 120, polling: int = 10):
        self.api_key = api_key
        self.timeout = timeout
        self.polling = polling
        self._solver = None

    def _get_solver(self):
        if self._solver is None:
            try:
                from twocaptcha import AsyncTwoCaptcha
                self._solver = AsyncTwoCaptcha(
                    apiKey=self.api_key,
                    defaultTimeout=self.timeout,
                    pollingInterval=self.polling,
                )
            except ImportError:
                logger.warning("[2captcha] 2captcha-python not installed. pip install 2captcha-python")
                return None
        return self._solver

    async def solve_recaptcha_v2(self, sitekey: str, url: str, **kw) -> Optional[str]:
        solver = self._get_solver()
        if not solver:
            return None
        try:
            result = await solver.recaptcha(sitekey=sitekey, url=url, **kw)
            token = result.get("code") if isinstance(result, dict) else str(result)
            logger.info(f"[2captcha] reCAPTCHA v2 solved for {url}")
            return token
        except Exception as e:
            logger.error(f"[2captcha] reCAPTCHA v2 error: {e}")
            return None

    async def solve_recaptcha_v3(self, sitekey: str, url: str, **kw) -> Optional[str]:
        solver = self._get_solver()
        if not solver:
            return None
        try:
            result = await solver.recaptcha(
                sitekey=sitekey, url=url, version="v3",
                action=kw.get("action", "verify"),
                score=kw.get("min_score", 0.3),
                **{k: v for k, v in kw.items() if k not in ("action", "min_score")},
            )
            token = result.get("code") if isinstance(result, dict) else str(result)
            logger.info(f"[2captcha] reCAPTCHA v3 solved for {url}")
            return token
        except Exception as e:
            logger.error(f"[2captcha] reCAPTCHA v3 error: {e}")
            return None

    async def solve_hcaptcha(self, sitekey: str, url: str, **kw) -> Optional[str]:
        solver = self._get_solver()
        if not solver:
            return None
        try:
            result = await solver.hcaptcha(sitekey=sitekey, url=url, **kw)
            token = result.get("code") if isinstance(result, dict) else str(result)
            logger.info(f"[2captcha] hCaptcha solved for {url}")
            return token
        except Exception as e:
            logger.error(f"[2captcha] hCaptcha error: {e}")
            return None

    async def solve_turnstile(self, sitekey: str, url: str, **kw) -> Optional[str]:
        solver = self._get_solver()
        if not solver:
            return None
        try:
            result = await solver.turnstile(sitekey=sitekey, url=url, **kw)
            token = result.get("code") if isinstance(result, dict) else str(result)
            logger.info(f"[2captcha] Turnstile solved for {url}")
            return token
        except Exception as e:
            logger.error(f"[2captcha] Turnstile error: {e}")
            return None

    async def solve_funcaptcha(self, sitekey: str, url: str, **kw) -> Optional[str]:
        solver = self._get_solver()
        if not solver:
            return None
        try:
            result = await solver.funcaptcha(sitekey=sitekey, url=url, **kw)
            token = result.get("code") if isinstance(result, dict) else str(result)
            logger.info(f"[2captcha] FunCaptcha solved for {url}")
            return token
        except Exception as e:
            logger.error(f"[2captcha] FunCaptcha error: {e}")
            return None

    async def solve_datadome(self, captcha_url: str, page_url: str, **kw) -> Optional[str]:
        solver = self._get_solver()
        if not solver:
            return None
        try:
            proxy = kw.pop("proxy", None)
            user_agent = kw.pop("user_agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                                "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36")
            result = await solver.datadome(
                captcha_url=captcha_url,
                pageurl=page_url,
                userAgent=user_agent,
                proxy=proxy,
                **kw,
            )
            token = result.get("code") if isinstance(result, dict) else str(result)
            logger.info(f"[2captcha] DataDome solved for {page_url}")
            return token
        except Exception as e:
            logger.error(f"[2captcha] DataDome error: {e}")
            return None

    async def solve_geetest_v3(self, gt: str, challenge: str, url: str, **kw) -> Optional[str]:
        solver = self._get_solver()
        if not solver:
            return None
        try:
            result = await solver.geetest(gt=gt, challenge=challenge, url=url, **kw)
            # Returns JSON with challenge/validate/seccode
            return str(result) if result else None
        except Exception as e:
            logger.error(f"[2captcha] GeeTest v3 error: {e}")
            return None

    async def solve_geetest_v4(self, captcha_id: str, url: str, **kw) -> Optional[str]:
        solver = self._get_solver()
        if not solver:
            return None
        try:
            result = await solver.geetest_v4(captcha_id=captcha_id, url=url, **kw)
            return str(result) if result else None
        except Exception as e:
            logger.error(f"[2captcha] GeeTest v4 error: {e}")
            return None

    async def solve_image(self, image_path_or_base64: str, **kw) -> Optional[str]:
        solver = self._get_solver()
        if not solver:
            return None
        try:
            result = await solver.normal(image_path_or_base64, **kw)
            token = result.get("code") if isinstance(result, dict) else str(result)
            return token
        except Exception as e:
            logger.error(f"[2captcha] Image captcha error: {e}")
            return None

    async def get_balance(self) -> float:
        solver = self._get_solver()
        if not solver:
            return 0.0
        try:
            return float(await solver.balance())
        except Exception as e:
            logger.error(f"[2captcha] Balance check error: {e}")
            return 0.0


# ────────────────────────── NOPECHA PROVIDER ──────────────────────────

class NopeCHAProvider(CaptchaProvider):
    """NopeCHA provider using nopecha async client."""
    name = "nopecha"

    def __init__(self, api_key: str):
        self.api_key = api_key
        self._client = None

    def _get_client(self):
        if self._client is None:
            try:
                from nopecha.api.urllib import URLLibAPIClient
                self._client = URLLibAPIClient(self.api_key)
            except ImportError:
                logger.warning("[NopeCHA] nopecha not installed. pip install nopecha")
                return None
        return self._client

    async def _solve_async(self, method_name: str, *args, **kwargs) -> Optional[str]:
        """Run a sync NopeCHA client method in executor."""
        client = self._get_client()
        if not client:
            return None
        method = getattr(client, method_name, None)
        if not method:
            logger.error(f"[NopeCHA] Method {method_name} not found on client")
            return None
        try:
            result = await asyncio.get_event_loop().run_in_executor(
                None, lambda: method(*args, **kwargs)
            )
            if result and isinstance(result, dict):
                return result.get("data") or result.get("token")
            return str(result) if result else None
        except Exception as e:
            logger.error(f"[NopeCHA] {method_name} error: {e}")
            return None

    async def solve_recaptcha_v2(self, sitekey: str, url: str, **kw) -> Optional[str]:
        token = await self._solve_async("solve_recaptcha", sitekey, url)
        if token:
            logger.info(f"[NopeCHA] reCAPTCHA v2 solved for {url}")
        return token

    async def solve_recaptcha_v3(self, sitekey: str, url: str, **kw) -> Optional[str]:
        # NopeCHA uses same method for v2/v3
        token = await self._solve_async("solve_recaptcha", sitekey, url)
        if token:
            logger.info(f"[NopeCHA] reCAPTCHA v3 solved for {url}")
        return token

    async def solve_hcaptcha(self, sitekey: str, url: str, **kw) -> Optional[str]:
        token = await self._solve_async("solve_hcaptcha", sitekey, url)
        if token:
            logger.info(f"[NopeCHA] hCaptcha solved for {url}")
        return token

    async def solve_turnstile(self, sitekey: str, url: str, **kw) -> Optional[str]:
        token = await self._solve_async("solve_turnstile", sitekey, url)
        if token:
            logger.info(f"[NopeCHA] Turnstile solved for {url}")
        return token

    async def solve_funcaptcha(self, sitekey: str, url: str, **kw) -> Optional[str]:
        token = await self._solve_async("solve_funcaptcha", sitekey, url)
        if token:
            logger.info(f"[NopeCHA] FunCaptcha solved for {url}")
        return token

    async def get_balance(self) -> float:
        client = self._get_client()
        if not client:
            return 0.0
        try:
            result = await asyncio.get_event_loop().run_in_executor(
                None, lambda: client.status()
            )
            if isinstance(result, dict):
                return float(result.get("credit", 0))
            return 0.0
        except Exception as e:
            logger.error(f"[NopeCHA] Balance check error: {e}")
            return 0.0


# ────────────────────────── ANTI-CAPTCHA PROVIDER ──────────────────────────

class AntiCaptchaProvider(CaptchaProvider):
    """Anti-captcha.com provider using anticaptchaofficial."""
    name = "anticaptcha"

    def __init__(self, api_key: str):
        self.api_key = api_key

    async def _solve_with_task(self, task_class_name: str, setup_fn) -> Optional[str]:
        """Generic solve using anticaptchaofficial task classes."""
        try:
            import anticaptchaofficial
            mod = __import__(f"anticaptchaofficial.{task_class_name.lower()}",
                           fromlist=[task_class_name])
            TaskClass = getattr(mod, task_class_name, None)
            if not TaskClass:
                logger.error(f"[AntiCaptcha] Task class {task_class_name} not found")
                return None

            solver = TaskClass()
            solver.set_key(self.api_key)
            setup_fn(solver)

            result = await asyncio.get_event_loop().run_in_executor(
                None, solver.solve_and_return_solution
            )
            if result and result != 0:
                return str(result)
            error = getattr(solver, "error_code", "unknown")
            logger.error(f"[AntiCaptcha] Solve failed: {error}")
            return None
        except ImportError:
            logger.warning("[AntiCaptcha] anticaptchaofficial not installed. "
                         "pip install anticaptchaofficial")
            return None
        except Exception as e:
            logger.error(f"[AntiCaptcha] {task_class_name} error: {e}")
            return None

    async def solve_recaptcha_v2(self, sitekey: str, url: str, **kw) -> Optional[str]:
        def setup(s):
            s.set_website_url(url)
            s.set_website_key(sitekey)
        token = await self._solve_with_task("recaptchaV2Proxyless", setup)
        if token:
            logger.info(f"[AntiCaptcha] reCAPTCHA v2 solved for {url}")
        return token

    async def solve_recaptcha_v3(self, sitekey: str, url: str, **kw) -> Optional[str]:
        def setup(s):
            s.set_website_url(url)
            s.set_website_key(sitekey)
            s.set_page_action(kw.get("action", "verify"))
            s.set_min_score(kw.get("min_score", 0.3))
        token = await self._solve_with_task("recaptchaV3Proxyless", setup)
        if token:
            logger.info(f"[AntiCaptcha] reCAPTCHA v3 solved for {url}")
        return token

    async def solve_hcaptcha(self, sitekey: str, url: str, **kw) -> Optional[str]:
        def setup(s):
            s.set_website_url(url)
            s.set_website_key(sitekey)
        token = await self._solve_with_task("hCaptchaProxyless", setup)
        if token:
            logger.info(f"[AntiCaptcha] hCaptcha solved for {url}")
        return token

    async def solve_turnstile(self, sitekey: str, url: str, **kw) -> Optional[str]:
        def setup(s):
            s.set_website_url(url)
            s.set_website_key(sitekey)
        token = await self._solve_with_task("turnstileProxyless", setup)
        if token:
            logger.info(f"[AntiCaptcha] Turnstile solved for {url}")
        return token

    async def solve_funcaptcha(self, sitekey: str, url: str, **kw) -> Optional[str]:
        def setup(s):
            s.set_website_url(url)
            s.set_website_key(sitekey)
        token = await self._solve_with_task("funCaptchaProxyless", setup)
        if token:
            logger.info(f"[AntiCaptcha] FunCaptcha solved for {url}")
        return token

    async def solve_image(self, image_path_or_base64: str, **kw) -> Optional[str]:
        def setup(s):
            if image_path_or_base64.startswith("data:") or len(image_path_or_base64) > 200:
                # Base64 encoded
                b64 = image_path_or_base64
                if "base64," in b64:
                    b64 = b64.split("base64,")[1]
                s.set_body(b64)
            else:
                s.set_file_path(image_path_or_base64)
        token = await self._solve_with_task("imagecaptcha", setup)
        if token:
            logger.info("[AntiCaptcha] Image captcha solved")
        return token

    async def get_balance(self) -> float:
        try:
            from anticaptchaofficial.antinetworking import antiNetworking
            client = antiNetworking()
            client.client_key = self.api_key
            result = await asyncio.get_event_loop().run_in_executor(
                None, client.get_balance
            )
            return float(result) if result else 0.0
        except ImportError:
            return 0.0
        except Exception as e:
            logger.error(f"[AntiCaptcha] Balance check error: {e}")
            return 0.0


# ────────────────────────── MAIN CAPTCHA SOLVER ──────────────────────────

class CaptchaSolver:
    """
    Multi-provider async captcha solver with fallback chain.

    Tries providers in configured order. If primary fails,
    falls back to next provider. Tracks stats and costs.
    """

    def __init__(
        self,
        twocaptcha_key: str = "",
        nopecha_key: str = "",
        anticaptcha_key: str = "",
        provider_order: Optional[List[str]] = None,
        enabled: bool = True,
        max_solve_time: float = 180.0,
        auto_solve_search: bool = True,   # Auto-solve captchas blocking search engines
        auto_solve_target: bool = False,  # Auto-solve captchas on target sites
    ):
        self.enabled = enabled
        self.max_solve_time = max_solve_time
        self.auto_solve_search = auto_solve_search
        self.auto_solve_target = auto_solve_target
        self.stats = SolverStats()

        # Build provider chain
        self._providers: List[CaptchaProvider] = []
        provider_map = {}

        if twocaptcha_key:
            provider_map["2captcha"] = TwoCaptchaProvider(twocaptcha_key)
        if nopecha_key:
            provider_map["nopecha"] = NopeCHAProvider(nopecha_key)
        if anticaptcha_key:
            provider_map["anticaptcha"] = AntiCaptchaProvider(anticaptcha_key)

        # Order providers
        order = provider_order or ["nopecha", "2captcha", "anticaptcha"]
        for name in order:
            if name in provider_map:
                self._providers.append(provider_map[name])
        # Add any remaining providers not in the explicit order
        for name, prov in provider_map.items():
            if prov not in self._providers:
                self._providers.append(prov)

    @property
    def available(self) -> bool:
        """Whether any provider is configured."""
        return self.enabled and len(self._providers) > 0

    @property
    def provider_names(self) -> List[str]:
        return [p.name for p in self._providers]

    async def solve(self, captcha_info: Dict[str, Any], url: str, **kw) -> SolveResult:
        """
        Solve a captcha using provider fallback chain.

        Args:
            captcha_info: Dict from SitekeyExtractor.detect() with type, sitekey, etc.
            url: The page URL where the captcha appears
            **kw: Additional params passed to the provider

        Returns:
            SolveResult with token or error
        """
        if not self.available:
            return SolveResult(success=False, error="No captcha providers configured")

        if not captcha_info:
            return SolveResult(success=False, error="No captcha info provided")

        ctype = captcha_info.get("type")
        sitekey = captcha_info.get("sitekey")

        if not ctype:
            return SolveResult(success=False, error="Unknown captcha type")

        logger.info(f"[CaptchaSolver] Solving {ctype} for {url} "
                   f"(sitekey={sitekey[:10]}...)" if sitekey else
                   f"[CaptchaSolver] Solving {ctype} for {url}")

        start = time.time()

        for provider in self._providers:
            try:
                token = await asyncio.wait_for(
                    self._dispatch(provider, ctype, captcha_info, url, **kw),
                    timeout=self.max_solve_time,
                )
                if token:
                    elapsed = time.time() - start
                    result = SolveResult(
                        success=True,
                        token=token,
                        provider=provider.name,
                        captcha_type=ctype,
                        solve_time=elapsed,
                    )
                    self.stats.record(result)
                    return result
            except asyncio.TimeoutError:
                logger.warning(f"[CaptchaSolver] {provider.name} timed out solving {ctype}")
            except Exception as e:
                logger.error(f"[CaptchaSolver] {provider.name} error: {e}")

        elapsed = time.time() - start
        result = SolveResult(
            success=False,
            captcha_type=ctype,
            solve_time=elapsed,
            error=f"All {len(self._providers)} providers failed for {ctype}",
        )
        self.stats.record(result)
        return result

    async def _dispatch(self, provider: CaptchaProvider, ctype: str,
                       info: Dict[str, Any], url: str, **kw) -> Optional[str]:
        """Route to the correct provider method based on captcha type."""
        sitekey = info.get("sitekey")

        if ctype == CaptchaType.RECAPTCHA_V2 and sitekey:
            return await provider.solve_recaptcha_v2(sitekey, url, **kw)
        elif ctype == CaptchaType.RECAPTCHA_V3 and sitekey:
            return await provider.solve_recaptcha_v3(sitekey, url, **kw)
        elif ctype == CaptchaType.HCAPTCHA and sitekey:
            return await provider.solve_hcaptcha(sitekey, url, **kw)
        elif ctype == CaptchaType.TURNSTILE and sitekey:
            return await provider.solve_turnstile(sitekey, url, **kw)
        elif ctype == CaptchaType.FUNCAPTCHA and sitekey:
            return await provider.solve_funcaptcha(sitekey, url, **kw)
        elif ctype == CaptchaType.DATADOME:
            captcha_url = info.get("captcha_url", "")
            return await provider.solve_datadome(captcha_url, url, **kw)
        elif ctype == CaptchaType.GEETEST_V3:
            gt = info.get("gt", "")
            challenge = info.get("challenge", "")
            return await provider.solve_geetest_v3(gt, challenge, url, **kw)
        elif ctype == CaptchaType.GEETEST_V4:
            captcha_id = info.get("gt", "")  # gt field used as captcha_id
            return await provider.solve_geetest_v4(captcha_id, url, **kw)
        elif ctype == CaptchaType.IMAGE:
            image = info.get("image", "")
            return await provider.solve_image(image, **kw)

        logger.warning(f"[CaptchaSolver] Unsupported captcha type: {ctype} "
                      f"(sitekey={'present' if sitekey else 'missing'})")
        return None

    async def solve_from_html(self, html: str, url: str, **kw) -> SolveResult:
        """
        Detect captcha in HTML and solve it.

        Convenience method that combines SitekeyExtractor.detect() + solve().
        """
        info = SitekeyExtractor.detect(html)
        if not info:
            return SolveResult(success=False, error="No captcha detected in HTML")
        return await self.solve(info, url, **kw)

    async def get_balances(self) -> Dict[str, float]:
        """Get balance for all configured providers."""
        balances = {}
        for provider in self._providers:
            try:
                bal = await asyncio.wait_for(provider.get_balance(), timeout=10)
                balances[provider.name] = bal
            except Exception as e:
                balances[provider.name] = -1  # Error indicator
                logger.error(f"[CaptchaSolver] Balance check failed for {provider.name}: {e}")
        return balances

    def get_stats(self) -> Dict[str, Any]:
        """Get comprehensive solver statistics."""
        s = self.stats
        return {
            "enabled": self.enabled,
            "providers": self.provider_names,
            "auto_solve_search": self.auto_solve_search,
            "auto_solve_target": self.auto_solve_target,
            "total_attempts": s.total_attempts,
            "total_solved": s.total_solved,
            "total_failed": s.total_failed,
            "success_rate": f"{s.total_solved / s.total_attempts:.0%}" if s.total_attempts else "N/A",
            "total_cost": f"${s.total_cost:.4f}",
            "avg_solve_time": f"{s.total_time / s.total_solved:.1f}s" if s.total_solved else "N/A",
            "by_type": dict(s.by_type),
            "by_provider": dict(s.by_provider),
        }
