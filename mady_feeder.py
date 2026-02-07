"""
Mady Bot Auto-Feed Integration

Automatically feeds found gateway keys to Mady bot's scraped_keys.json
for immediate testing and validation.
"""

import os
import json
import asyncio
from datetime import datetime
from typing import Dict, List, Optional
from dataclasses import dataclass, field
from pathlib import Path
from loguru import logger


@dataclass
class MadyFeederConfig:
    """Configuration for Mady bot feeder."""
    enabled: bool = True
    mady_path: str = "/home/null/Desktop/Mady7.0.2/Mady_Version7.0.0"
    scraped_keys_file: str = "scraped_keys.json"
    auto_test: bool = False  # Auto-trigger gateway test after feeding
    deduplicate: bool = True  # Skip already-fed keys


class MadyFeeder:
    """Feeds gateway keys to Mady bot for testing.
    
    XDumpGO-complete support for 50+ gateway types!
    """
    
    # Map MedyDorker key types to Mady bot key types (comprehensive XDumpGO mapping)
    KEY_TYPE_MAP = {
        # ========== STRIPE ==========
        "stripe_pk": "stripe_pk",
        "stripe_publishable_key": "stripe_pk",
        "Stripe Publishable Key": "stripe_pk",
        "stripe_sk": "stripe_sk",
        "stripe_secret_key": "stripe_sk",
        "Stripe Secret Key": "stripe_sk",
        "stripe_rk": "stripe_rk",
        "Stripe Restricted Key": "stripe_rk",
        "stripe_whsec": "stripe_webhook",
        "Stripe Webhook Secret": "stripe_webhook",
        "stripe_pk_test": "stripe_pk_test",
        "stripe_sk_test": "stripe_sk_test",
        "stripe_acct": "stripe_acct",
        "stripe_client_secret": "stripe_client_secret",
        
        # ========== BRAINTREE ==========
        "braintree_token": "braintree_token",
        "braintree_client_token": "braintree_token",
        "Braintree Client Token": "braintree_token",
        "braintree_merchant": "braintree_merchant",
        "Braintree Merchant ID": "braintree_merchant",
        "braintree_private": "braintree_private",
        "braintree_public": "braintree_public",
        
        # ========== PAYPAL ==========
        "paypal_client": "paypal_client",
        "paypal_client_id": "paypal_client",
        "PayPal Client ID": "paypal_client",
        "paypal_secret": "paypal_secret",
        "PayPal Secret": "paypal_secret",
        "paypal_sdk": "paypal_sdk",
        "paypal_merchant": "paypal_merchant",
        "paypal_access_token": "paypal_access_token",
        
        # ========== SQUARE ==========
        "square_token": "square_token",
        "Square Access Token": "square_token",
        "square_secret": "square_secret",
        "Square OAuth Secret": "square_secret",
        "square_app": "square_app",
        "square_location": "square_location",
        
        # ========== ADYEN ==========
        "adyen_key": "adyen_key",
        "Adyen API Key": "adyen_key",
        "adyen_client": "adyen_client",
        "adyen_merchant": "adyen_merchant",
        
        # ========== RAZORPAY ==========
        "razorpay_key": "razorpay_key",
        "Razorpay Key ID": "razorpay_key",
        "razorpay_secret": "razorpay_secret",
        
        # ========== MOLLIE ==========
        "mollie_live": "mollie_live",
        "mollie_test": "mollie_test",
        
        # ========== KLARNA ==========
        "klarna_key": "klarna",
        "klarna_merchant": "klarna_merchant",
        
        # ========== AFFIRM ==========
        "affirm_public": "affirm_public",
        "affirm_private": "affirm_private",
        
        # ========== AFTERPAY ==========
        "afterpay_merchant": "afterpay",
        "afterpay_secret": "afterpay_secret",
        
        # ========== SEZZLE ==========
        "sezzle_public": "sezzle_public",
        "sezzle_private": "sezzle_private",
        
        # ========== AUTHORIZE.NET ==========
        "authnet_login": "authnet_login",
        "authnet_key": "authnet_key",
        "Authorize.net Login ID": "authnet_login",
        "Authorize.net Transaction Key": "authnet_key",
        
        # ========== CHECKOUT.COM ==========
        "checkout_pk": "checkout_pk",
        "Checkout.com PK": "checkout_pk",
        "checkout_sk": "checkout_sk",
        
        # ========== WORLDPAY ==========
        "worldpay_key": "worldpay_key",
        "worldpay_client": "worldpay_client",
        
        # ========== NMI ==========
        "nmi_key": "nmi_key",
        "nmi_token": "nmi_token",
        
        # ========== 2CHECKOUT ==========
        "2checkout_merchant": "2checkout_merchant",
        "2checkout_secret": "2checkout_secret",
        
        # ========== PAYU ==========
        "payu_key": "payu_key",
        "payu_salt": "payu_salt",
        
        # ========== CYBERSOURCE ==========
        "cybersource_merchant": "cybersource_merchant",
        "cybersource_key": "cybersource_key",
        
        # ========== FIRST DATA ==========
        "firstdata_merchant": "firstdata_merchant",
        "firstdata_secret": "firstdata_secret",
        
        # ========== GLOBAL PAYMENTS ==========
        "globalpay_key": "globalpay_key",
        "globalpay_merchant": "globalpay_merchant",
        
        # ========== PAYSAFE/SKRILL ==========
        "paysafe_key": "paysafe_key",
        "skrill_merchant": "skrill_merchant",
        "skrill_secret": "skrill_secret",
        
        # ========== GOCARDLESS ==========
        "gocardless_token": "gocardless_token",
        
        # ========== RECURLY ==========
        "recurly_key": "recurly_key",
        "recurly_public": "recurly_public",
        
        # ========== CHARGEBEE ==========
        "chargebee_key": "chargebee_key",
        "chargebee_site": "chargebee_site",
        
        # ========== PADDLE ==========
        "paddle_vendor": "paddle_vendor",
        "paddle_key": "paddle_key",
        
        # ========== GUMROAD ==========
        "gumroad_token": "gumroad_token",
        
        # ========== LEMONSQUEEZY ==========
        "lemonsqueezy_key": "lemonsqueezy_key",
        
        # ========== FASTSPRING ==========
        "fastspring_key": "fastspring_key",
        
        # ========== BLUESNAP ==========
        "bluesnap_pass": "bluesnap_pass",
        
        # ========== SPREEDLY ==========
        "spreedly_env": "spreedly_env",
        "spreedly_secret": "spreedly_secret",
        
        # ========== PLAID ==========
        "plaid_client": "plaid_client",
        "plaid_secret": "plaid_secret",
        "plaid_public": "plaid_public",
        
        # ========== WEPAY ==========
        "wepay_client": "wepay_client",
        "wepay_token": "wepay_token",
        
        # ========== DWOLLA ==========
        "dwolla_key": "dwolla_key",
        "dwolla_secret": "dwolla_secret",
        
        # ========== INDIAN GATEWAYS ==========
        "instamojo_key": "instamojo_key",
        "instamojo_token": "instamojo_token",
        "paytm_key": "paytm_key",
        "paytm_mid": "paytm_mid",
        "phonepe_merchant": "phonepe_merchant",
        "phonepe_salt": "phonepe_salt",
    }
    
    # Gateway types that Mady bot can test
    SUPPORTED_GATEWAYS = [
        'stripe_pk', 'stripe_sk', 'stripe_rk', 'stripe_webhook', 'stripe_acct',
        'braintree_token', 'braintree_merchant', 'braintree',
        'paypal_client', 'paypal_secret', 'paypal',
        'square_token', 'square_secret', 'square',
        'adyen_key', 'adyen_client', 'adyen',
        'razorpay_key', 'razorpay_secret', 'razorpay',
        'mollie_live', 'mollie_test', 'mollie',
        'klarna', 'affirm', 'afterpay', 'sezzle',
        'authnet_login', 'authnet_key', 'authorize',
        'checkout_pk', 'checkout_sk', 'checkout',
        'worldpay', 'nmi', '2checkout', 'payu',
        'cybersource', 'firstdata', 'globalpay',
        'paysafe', 'skrill', 'gocardless', 'recurly',
        'chargebee', 'paddle', 'gumroad', 'lemonsqueezy',
        'fastspring', 'bluesnap', 'spreedly',
        'plaid', 'wepay', 'dwolla',
        'instamojo', 'paytm', 'phonepe',
    ]
    
    def __init__(self, config: Optional[MadyFeederConfig] = None):
        self.config = config or MadyFeederConfig()
        self.scraped_keys_path = os.path.join(
            self.config.mady_path, 
            self.config.scraped_keys_file
        )
        self._fed_keys: set = set()  # Track what we've already fed
        self._load_existing_keys()
    
    def _load_existing_keys(self):
        """Load existing keys to avoid duplicates."""
        if not self.config.deduplicate:
            return
        
        try:
            if os.path.exists(self.scraped_keys_path):
                with open(self.scraped_keys_path, 'r') as f:
                    data = json.load(f)
                    for entry in data:
                        for key_type, keys in entry.get('keys', []):
                            for key in keys:
                                self._fed_keys.add(key)
                logger.debug(f"Loaded {len(self._fed_keys)} existing keys from Mady")
        except Exception as e:
            logger.warning(f"Could not load existing Mady keys: {e}")
    
    def _normalize_key_type(self, key_type: str) -> str:
        """Normalize key type to Mady bot format."""
        return self.KEY_TYPE_MAP.get(key_type, key_type.lower().replace(' ', '_'))
    
    def _is_supported_gateway(self, key_type: str) -> bool:
        """Check if key type is supported by Mady bot (50+ gateways!)."""
        normalized = self._normalize_key_type(key_type)
        return any(s in normalized for s in self.SUPPORTED_GATEWAYS)
    
    def feed_gateway(self, url: str, key_type: str, key_value: str, 
                     extra: Optional[Dict] = None) -> bool:
        """Feed a single gateway key to Mady bot.
        
        Args:
            url: Source URL where key was found
            key_type: Type of gateway key
            key_value: The actual key value
            extra: Optional additional metadata
            
        Returns:
            True if successfully fed, False otherwise
        """
        if not self.config.enabled:
            return False
        
        if not self._is_supported_gateway(key_type):
            logger.debug(f"Skipping unsupported gateway type: {key_type}")
            return False
        
        # Check for duplicates
        if key_value in self._fed_keys:
            logger.debug(f"Skipping duplicate key: {key_value[:20]}...")
            return False
        
        normalized_type = self._normalize_key_type(key_type)
        
        try:
            # Load existing keys
            existing = []
            if os.path.exists(self.scraped_keys_path):
                with open(self.scraped_keys_path, 'r') as f:
                    existing = json.load(f)
            
            # Check if URL already has entry
            found_url = False
            for entry in existing:
                if entry.get('url') == url:
                    # Add key to existing entry
                    key_found = False
                    for kt, keys in entry.get('keys', []):
                        if kt == normalized_type:
                            if key_value not in keys:
                                keys.append(key_value)
                            key_found = True
                            break
                    if not key_found:
                        entry.setdefault('keys', []).append([normalized_type, [key_value]])
                    found_url = True
                    break
            
            # Create new entry if URL not found
            if not found_url:
                new_entry = {
                    "url": url,
                    "keys": [[normalized_type, [key_value]]],
                    "source": "medydorker",
                    "timestamp": datetime.now().isoformat(),
                }
                if extra:
                    new_entry['extra'] = extra
                existing.append(new_entry)
            
            # Write back
            with open(self.scraped_keys_path, 'w') as f:
                json.dump(existing, f, indent=2)
            
            self._fed_keys.add(key_value)
            logger.info(f"Fed gateway to Mady: {normalized_type} from {url[:50]}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to feed key to Mady: {e}")
            return False
    
    def feed_batch(self, gateways: List[Dict]) -> int:
        """Feed multiple gateways to Mady bot.
        
        Args:
            gateways: List of gateway dicts with url, type, value keys
            
        Returns:
            Number of gateways successfully fed
        """
        fed_count = 0
        for gw in gateways:
            url = gw.get('url', '')
            key_type = gw.get('type', '')
            key_value = gw.get('value', '')
            if url and key_type and key_value:
                if self.feed_gateway(url, key_type, key_value):
                    fed_count += 1
        return fed_count
    
    def get_stats(self) -> Dict:
        """Get feeder statistics."""
        total_in_mady = 0
        try:
            if os.path.exists(self.scraped_keys_path):
                with open(self.scraped_keys_path, 'r') as f:
                    data = json.load(f)
                    total_in_mady = len(data)
        except:
            pass
        
        return {
            "enabled": self.config.enabled,
            "mady_path": self.config.mady_path,
            "keys_fed_this_session": len(self._fed_keys),
            "total_entries_in_mady": total_in_mady,
        }


# Singleton instance for easy access
_feeder: Optional[MadyFeeder] = None


def get_feeder(config: Optional[MadyFeederConfig] = None) -> MadyFeeder:
    """Get or create the global feeder instance."""
    global _feeder
    if _feeder is None:
        _feeder = MadyFeeder(config)
    return _feeder


def feed_to_mady(url: str, key_type: str, key_value: str, extra: Optional[Dict] = None) -> bool:
    """Convenience function to feed a gateway to Mady bot."""
    return get_feeder().feed_gateway(url, key_type, key_value, extra)
