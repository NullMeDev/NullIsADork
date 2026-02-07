"""
Dorker Configuration
"""

import os
from dataclasses import dataclass, field
from typing import List, Optional

@dataclass
class DorkerConfig:
    """Configuration for the dorking tool."""
    
    # Telegram settings
    telegram_bot_token: str = os.getenv("DORKER_BOT_TOKEN", "")
    telegram_chat_id: str = os.getenv("DORKER_CHAT_ID", "")
    
    # Search settings
    search_delay_min: int = 10  # Minimum seconds between searches
    search_delay_max: int = 30  # Maximum seconds between searches
    results_per_dork: int = 15  # Results to fetch per dork
    
    # Validation settings
    validation_timeout: int = 15  # Timeout for site validation
    max_concurrent_validations: int = 5  # Concurrent validation requests
    
    # Proxy settings
    use_proxies: bool = True
    proxy_file: str = "proxies.txt"
    rotate_proxy_every: int = 5  # Rotate proxy every N searches
    
    # Storage
    found_sites_file: str = "found_sites.json"
    seen_domains_file: str = "seen_domains.txt"
    
    # Run settings
    continuous: bool = True  # Run continuously
    cycle_delay: int = 300  # Seconds between full dork cycles (5 min)
    
    # Dorks to use
    dorks: List[str] = field(default_factory=lambda: [
        # ========== STRIPE PAYMENT SITES ==========
        # High priority - Donation sites
        'site:*.org intitle:donate intext:"pk_live_" -recaptcha -cloudflare',
        'site:*.org "donate now" intext:"stripe" -captcha',
        'site:*.church donate intext:"stripe"',
        'site:*.org "give" OR "support us" intext:"pk_live_"',
        'site:*.foundation "support" intext:"stripe" checkout',
        'site:*.charity intext:"pk_live_" donate',
        
        # WooCommerce sites
        'inurl:my-account/add-payment-method "woocommerce" -github',
        '"powered by woocommerce" intext:"stripe" -captcha -recaptcha',
        'intext:"wc_stripe_params" -github -stackoverflow',
        'inurl:checkout "woocommerce" intext:"pk_live_"',
        'inurl:wp-admin "woocommerce" intext:"stripe" checkout',
        '"woocommerce_stripe_params" -github -docs',
        
        # Digital products
        '"digital download" intext:"stripe" checkout -captcha',
        '"instant download" intext:"pk_live_" -github',
        '"ebook" OR "course" intext:"stripe" checkout',
        '"pdf download" payment intext:"stripe"',
        '"software license" checkout intext:"pk_live_"',
        
        # Membership/Subscription
        'intitle:"membership" intext:"stripe" inurl:signup -recaptcha',
        '"subscription" "signup" intext:"pk_live_" -github',
        '"free trial" intext:"stripe" "credit card"',
        '"recurring payment" intext:"stripe" checkout',
        'inurl:subscribe intext:"pk_live_" -docs',
        '"monthly plan" OR "yearly plan" intext:"stripe"',
        
        # Small businesses
        'inurl:shop intext:"woocommerce" intext:"stripe" -captcha',
        '"add to cart" intext:"pk_live_" -shopify -bigcommerce -github',
        'inurl:store checkout intext:"stripe" -docs',
        '"online store" payment intext:"pk_live_"',
        
        # Regional (often less security)
        'site:*.co.uk "donate" intext:"stripe" -recaptcha',
        'site:*.com.au "checkout" intext:"woocommerce" intext:"stripe"',
        'site:*.ca "donate" intext:"pk_live_" -cloudflare',
        'site:*.eu payment intext:"stripe" -captcha',
        'site:*.nz checkout intext:"pk_live_"',
        'site:*.ie "buy now" intext:"stripe"',
        
        # Niche markets
        '"pet" OR "animal" "donate" intext:"stripe" site:*.org',
        '"school" OR "education" "donate" intext:"pk_live_"',
        '"nonprofit" "support" intext:"stripe" checkout',
        '"church" OR "ministry" donate intext:"stripe"',
        '"food bank" OR "shelter" donate intext:"pk_live_"',
        '"medical" OR "health" donate intext:"stripe"',
        
        # ========== VPS / HOSTING SITES ==========
        '"vps hosting" checkout intext:"stripe" -docs',
        '"cloud hosting" payment intext:"pk_live_"',
        '"dedicated server" intext:"stripe" order -github',
        '"web hosting" inurl:checkout intext:"stripe"',
        'intitle:"order vps" intext:"pk_live_"',
        '"reseller hosting" payment intext:"stripe"',
        '"server rental" checkout intext:"stripe"',
        '"colocation" OR "colo" payment intext:"pk_live_"',
        '"rdp" OR "remote desktop" checkout intext:"stripe"',
        '"seedbox" payment intext:"stripe" -docs',
        
        # ========== PROXY / VPN SITES ==========
        '"proxy" OR "proxies" checkout intext:"stripe" -docs',
        '"private proxy" purchase intext:"pk_live_"',
        '"vpn service" payment intext:"stripe"',
        '"residential proxy" checkout intext:"stripe"',
        '"datacenter proxy" intext:"pk_live_" order',
        '"socks5" OR "socks4" payment intext:"stripe"',
        'intitle:"buy proxy" intext:"stripe"',
        '"proxy plan" checkout intext:"pk_live_"',
        '"rotating proxy" payment intext:"stripe"',
        
        # ========== GIFT CARDS / VOUCHERS ==========
        '"gift card" purchase intext:"stripe" -amazon -ebay',
        '"digital gift card" checkout intext:"pk_live_"',
        '"voucher" buy intext:"stripe" -groupon',
        'inurl:giftcard checkout intext:"stripe"',
        '"prepaid card" intext:"pk_live_" purchase',
        '"store credit" payment intext:"stripe"',
        '"gift certificate" checkout intext:"stripe"',
        '"redeem code" purchase intext:"pk_live_"',
        
        # ========== BRAINTREE SITES ==========
        'intext:"braintree" checkout -docs -github -stackoverflow',
        '"braintree.payments" -docs -github',
        'inurl:checkout "braintree" payment',
        '"data-braintree" -github -gitlab',
        'intext:"braintree.client.create" -docs',
        '"braintree_client_token" -github',
        
        # ========== PAYPAL / OTHER GATEWAYS ==========
        '"paypal checkout" -docs -github intext:"client-id"',
        'intext:"authorize.net" checkout -docs',
        '"square payment" checkout -docs -github',
        'intext:"payment_method_nonce" checkout',
        
        # ========== GAMING / ENTERTAINMENT ==========
        '"game server" OR "minecraft" payment intext:"stripe"',
        '"discord bot" OR "bot hosting" checkout intext:"pk_live_"',
        '"gaming" checkout intext:"stripe" -steam -epic',
        'inurl:topup OR inurl:top-up intext:"stripe"',
        '"virtual currency" purchase intext:"pk_live_"',
        '"premium account" upgrade intext:"stripe"',
        
        # ========== SOFTWARE / SAAS ==========
        '"saas" OR "software as a service" trial intext:"stripe"',
        'inurl:pricing "free trial" intext:"pk_live_"',
        '"api access" payment intext:"stripe" -docs',
        '"premium features" upgrade intext:"stripe"',
        'inurl:billing checkout intext:"pk_live_"',
        
        # ========== RARE / MISC ==========
        '"sms verification" OR "phone verification" checkout intext:"stripe"',
        '"burner phone" OR "temp number" payment intext:"pk_live_"',
        '"captcha solving" checkout intext:"stripe"',
        '"email verification" service payment intext:"stripe"',
        '"account generator" intext:"pk_live_" purchase',
        '"boosting service" payment intext:"stripe"',
        
        # ========== NEW BATCH - INTERNATIONAL ==========
        'site:*.de intext:"stripe" checkout bezahlung',
        'site:*.fr paiement intext:"pk_live_" -captcha',
        'site:*.es pago intext:"stripe" checkout',
        'site:*.it pagamento intext:"pk_live_"',
        'site:*.nl betaling intext:"stripe"',
        'site:*.pl platnosc intext:"pk_live_"',
        'site:*.in "payment" intext:"stripe" -paytm',
        'site:*.br pagamento intext:"pk_live_"',
        'site:*.mx pago intext:"stripe"',
        'site:*.se betalning intext:"pk_live_"',
        
        # ========== SPECIFIC NICHES ==========
        '"yoga" OR "meditation" donate intext:"stripe"',
        '"art gallery" OR "artist" checkout intext:"pk_live_"',
        '"music lessons" OR "guitar lessons" payment intext:"stripe"',
        '"photography" checkout intext:"pk_live_" -shutterstock',
        '"tutoring" OR "tutor" payment intext:"stripe"',
        '"coaching" OR "mentor" checkout intext:"pk_live_"',
        '"wedding" OR "event" booking intext:"stripe"',
        '"fitness" OR "gym" membership intext:"pk_live_"',
        '"dance" OR "ballet" classes payment intext:"stripe"',
        '"martial arts" OR "karate" checkout intext:"pk_live_"',
        
        # ========== TICKETS & EVENTS ==========
        '"event tickets" checkout intext:"stripe"',
        '"concert tickets" purchase intext:"pk_live_"',
        '"festival" tickets intext:"stripe" checkout',
        '"workshop" registration intext:"pk_live_"',
        '"webinar" registration payment intext:"stripe"',
        '"conference" tickets intext:"pk_live_"',
        
        # ========== E-LEARNING ==========
        '"online course" enrollment intext:"stripe"',
        '"video course" purchase intext:"pk_live_"',
        '"certification" OR "certificate" payment intext:"stripe"',
        '"training program" checkout intext:"pk_live_"',
        '"masterclass" OR "workshop" intext:"stripe" enroll',
        
        # ========== PHYSICAL PRODUCTS ==========
        '"handmade" OR "artisan" shop intext:"stripe"',
        '"custom" OR "personalized" checkout intext:"pk_live_"',
        '"organic" OR "natural" shop intext:"stripe" -amazon',
        '"vintage" OR "antique" checkout intext:"pk_live_"',
        
        # ========== SERVICES ==========
        '"cleaning service" booking intext:"stripe"',
        '"consulting" payment intext:"pk_live_"',
        '"freelance" OR "freelancer" checkout intext:"stripe"',
        '"design service" payment intext:"pk_live_"',
        '"legal" OR "lawyer" payment intext:"stripe"',
        '"accounting" OR "bookkeeping" payment intext:"pk_live_"',
        
        # ========== CRYPTO / FINTECH ==========
        '"crypto" OR "bitcoin" payment intext:"stripe" -exchange',
        '"nft" OR "nfts" checkout intext:"pk_live_"',
        '"token" OR "tokens" purchase intext:"stripe" -github',
        
        # ========== FRESH WOOCOMMERCE ==========
        'site:*.shop woocommerce intext:"pk_live_"',
        'site:*.store woocommerce intext:"stripe"',
        'site:*.boutique checkout intext:"pk_live_"',
        'site:*.online shop intext:"stripe"',
        
        # ========== HIDDEN GEMS ==========
        '"accept credit cards" intext:"stripe" -docs',
        '"payment form" intext:"pk_live_" -github',
        '"checkout form" intext:"stripe" -tutorial',
        '"secure payment" intext:"pk_live_" -docs',
        '"pay now" button intext:"stripe" -documentation',
        '"card payment" intext:"pk_live_" checkout',
        
        # ========== SMALL SITES ==========
        'inurl:pay intext:"stripe" checkout',
        'inurl:order intext:"pk_live_" payment',
        'inurl:purchase intext:"stripe" -docs -github',
        'inurl:donate intext:"pk_live_" -recaptcha',
        'inurl:subscribe intext:"stripe" payment',
        'inurl:register intext:"pk_live_" payment',
        
        # ========== MEMBERSHIP SITES ==========
        '"member portal" payment intext:"stripe"',
        '"member area" checkout intext:"pk_live_"',
        '"members only" intext:"stripe" join',
        '"exclusive access" payment intext:"pk_live_"',
        '"premium membership" intext:"stripe"',
        
        # ========== BOOKING SITES ==========
        '"book now" payment intext:"stripe"',
        '"reserve" OR "reservation" checkout intext:"pk_live_"',
        '"appointment" booking intext:"stripe"',
        '"schedule" payment intext:"pk_live_"',
        
        # ========== RANDOM FRESH ==========
        'intext:"Stripe.js" checkout -github -docs',
        'intext:"stripe.elements" payment -stackoverflow',
        '"card-element" intext:"pk_live_" -github',
        '"stripe-checkout" intext:"pk_live_" -docs',
        'intext:"confirmCardPayment" checkout -github',
    ])
    
    # Domains to always skip
    skip_domains: List[str] = field(default_factory=lambda: [
        "github.com", "github.io", "githubusercontent.com",
        "stackoverflow.com", "stackexchange.com",
        "stripe.com", "stripe.dev",
        "wordpress.org", "wordpress.com",
        "woocommerce.com",
        "shopify.com", "myshopify.com",
        "facebook.com", "twitter.com", "youtube.com",
        "linkedin.com", "instagram.com",
        "medium.com", "reddit.com",
        "npmjs.com", "pypi.org",
        "docs.google.com", "drive.google.com",
        "pastebin.com", "codepen.io",
        "jsfiddle.net", "replit.com",
        "w3schools.com", "mozilla.org",
        "example.com", "localhost",
    ])


# Default config instance
config = DorkerConfig()
