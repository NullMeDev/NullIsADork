"""
Dynamic Dork Generator — XDumpGO-style pattern-based URL generation

Generates thousands of search dorks by combining keywords, page types,
parameters, and domains using configurable pattern templates.
"""

import os
import random
import itertools
from pathlib import Path
from typing import List, Dict, Set, Optional
from loguru import logger


class DorkGenerator:
    """Generates dork queries from keyword files and pattern templates."""

    # Pattern templates (from XDumpGO + custom additions)
    DEFAULT_PATTERNS = [
        # === SQLi-focused (find injectable URLs) ===
        'inurl:"(KW)(PT)?(PP)="',
        'inurl:"(PF)(PT)?(PP)=" (KW)',
        'site:*(DE) inurl:"(PT)?(PP)=" (KW)',
        'inurl:"(PP)=" "(KW)" ext:php',
        'inurl:"(PP)=" "(KW)" ext:asp',
        
        # === Payment gateway focused ===
        '"(KW)" intext:"pk_live_" -github -docs',
        '"(KW)" intext:"stripe" checkout -github',
        '"(KW)" intext:"braintree" payment -docs',
        '"(KW)" intext:"paypal" checkout -docs -github',
        'site:*(DE) "(KW)" intext:"pk_live_"',
        'site:*(DE) "(KW)" intext:"stripe" checkout',
        
        # === Secret/key extraction focused ===
        '"(KW)" intext:"sk_live_" -github -stackoverflow',
        '"(KW)" intext:"AKIA" -github -docs',
        '"(KW)" intext:"api_key" -github -docs',
        '"(KW)" intext:"secret_key" -github',
        '"(KW)" intext:"client_secret" -github',
        '"(KW)" intext:"access_token" -github',
        '"(KW)" filetype:env',
        '"(KW)" filetype:sql',
        '"(KW)" filetype:log',
        '"(KW)" filetype:conf',
        '"(KW)" filetype:cfg',
        '"(KW)" filetype:bak',
        
        # === Database exposure focused ===
        '"(KW)" inurl:phpmyadmin',
        '"(KW)" inurl:adminer',
        '"(KW)" intitle:"index of" "sql"',
        '"(KW)" intitle:"index of" "backup"',
        '"(KW)" intitle:"index of" "database"',
        '"(KW)" inurl:wp-config.php',
        '"(KW)" inurl:.env intext:"DB_PASSWORD"',
        '"(KW)" intext:"mysql_connect" ext:php',
        
        # === Admin panel focused ===
        'site:*(DE) inurl:admin "(KW)"',
        'site:*(DE) inurl:panel "(KW)"',
        'site:*(DE) inurl:dashboard "(KW)"',
        'site:*(DE) intitle:"admin" "(KW)"',
        
        # === Deep SQLi patterns (expanded) ===
        'inurl:"(PF)(PT)?(PP)=" "error" "sql"',
        'inurl:"(PF)(PT)?(PP)=" "mysql" "warning"',
        'site:*(DE) inurl:"(PT)?(PP)=" "checkout" OR "payment"',
        'inurl:"(PP)=" "(KW)" intext:"error"',
        
        # === Payment checkout URL patterns ===
        'inurl:"/checkout" "(KW)" intext:"pk_live_"',
        'inurl:"/payment" "(KW)" intext:"stripe" -docs',
        'inurl:"/donate" "(KW)" intext:"pk_live_" -captcha',
        'inurl:"/cart" "(KW)" intext:"stripe" -github',
        'inurl:"/billing" "(KW)" intext:"pk_live_"',
        'inurl:"/subscribe" "(KW)" intext:"stripe"',
        
        # === Exposed config/files ===
        '"(KW)" filetype:json "api_key" OR "secret" -github -npm',
        '"(KW)" filetype:xml "password" OR "secret" -github',
        '"(KW)" filetype:yml "api_key" OR "token" -github',
        '"(KW)" filetype:ini "password" OR "secret" -github',
        '"(KW)" filetype:properties "password" -github',
        
        # === International injectable ===
        'site:*(DE) inurl:"(PT)?(PP)=" "(KW)" -captcha',
        'site:*(DE) "(KW)" checkout intext:"stripe"',
    ]

    # High-value static dorks (always included)
    STATIC_DORKS = [
        # === EXPOSED CREDENTIALS/SECRETS ===
        'filetype:env "STRIPE_SECRET" OR "STRIPE_KEY" OR "sk_live_"',
        'filetype:env "DB_PASSWORD" OR "DATABASE_URL" -github',
        'filetype:env "AWS_SECRET" OR "AWS_ACCESS_KEY" -github',
        'filetype:env "PAYPAL_SECRET" OR "PAYPAL_CLIENT" -github',
        'filetype:env "BRAINTREE_PRIVATE" OR "BRAINTREE_MERCHANT" -github',
        'filetype:env "SQUARE_ACCESS_TOKEN" OR "SQUARE_APPLICATION" -github',
        'filetype:env "AUTHORIZE_LOGIN" OR "AUTHORIZE_TRANSACTION" -github',
        'filetype:env "ADYEN_API_KEY" OR "ADYEN_MERCHANT" -github',
        'filetype:env "CHECKOUT_SECRET" OR "CHECKOUT_PUBLIC" -github',
        'filetype:env "WORLDPAY_SERVICE" OR "WORLDPAY_MERCHANT" -github',
        'filetype:env "NMI_SECURITY_KEY" OR "NMI_USERNAME" -github',
        'filetype:sql "INSERT INTO" "card_number" OR "cc_number"',
        'filetype:sql "INSERT INTO" "payment" OR "transaction"',
        'filetype:sql "INSERT INTO" "users" "password"',
        'filetype:sql "CREATE TABLE" "credit_card" OR "billing"',
        'filetype:log "card_number" OR "cc_num" OR "cvv"',
        'filetype:log "sk_live_" OR "pk_live_"',
        'filetype:log "password" "email" "login"',
        'filetype:bak "stripe" OR "payment" OR "billing"',
        'filetype:cfg "password" OR "secret" OR "key"',
        'filetype:conf "mysql" "password" -docs',
        'filetype:ini "password" "database" -docs',
        'filetype:yaml "api_key" OR "secret_key" -github',
        'filetype:json "sk_live_" OR "pk_live_" -github -npm',
        'filetype:json "client_secret" "client_id" -github',
        'filetype:xml "password" "username" "jdbc"',
        'intitle:"index of" ".env"',
        'intitle:"index of" "wp-config.php"',
        'intitle:"index of" ".git"',
        'intitle:"index of" "backup.sql"',
        'intitle:"index of" "dump.sql"',
        'intitle:"index of" "database.sql"',
        'intitle:"index of" "cards" OR "payments" ext:csv',
        'intitle:"index of" "customers" ext:csv',
        'intitle:"index of" "credentials"',
        'intitle:"index of" "private"',
        'intitle:"index of" "secret"',
        'inurl:".env" intext:"STRIPE" -github -gitlab',
        'inurl:".env" intext:"PAYPAL" -github -gitlab',
        'inurl:".env" intext:"DB_HOST" -github -gitlab',
        'inurl:"wp-config.php" intext:"DB_PASSWORD" -github',
        'inurl:"config.php" intext:"mysql" "password" -github -docs',
        'inurl:"settings.py" intext:"SECRET_KEY" -github -docs',
        'inurl:"application.properties" intext:"spring.datasource.password" -github',
        'inurl:".git/config" -github',
        'inurl:".git/HEAD" -github',
        'inurl:"phpinfo.php" intext:"mysql"',
        'inurl:"/server-status" "Apache"',
        'inurl:"debug" filetype:log',
        'inurl:"error_log" OR "error.log"',
        
        # === EXPOSED DATABASES ===
        'intitle:"phpMyAdmin" intext:"Welcome to phpMyAdmin"',
        'intitle:"Adminer" intext:"Login" intext:"Server"',
        'intitle:"pgAdmin" intext:"Login"',
        'inurl:"/_utils" intitle:"Futon"',  # CouchDB
        'inurl:":9200" intitle:"elasticsearch"',
        'inurl:":27017" "mongodb"',
        'inurl:"phpmyadmin/index.php" -github',
        '"MongoDB Server Information" inurl:28017',
        'intitle:"Kibana" intext:"Dashboard"',
        'inurl:":5601" intitle:"Kibana"',
        'intitle:"Redis Commander"',
        'intitle:"RabbitMQ Management"',
        
        # === CARD DATA SPECIFIC ===
        'intext:"card_number" "expiry" "cvv" -github -docs',
        'intext:"credit_card" "billing_address" -github -docs -tutorial',
        'intext:"cc_number" OR "ccnum" filetype:sql',
        'intext:"pan_number" "expiration" -docs -github',
        '"card_number" "exp_month" "exp_year" "cvc" -stripe.com -docs',
        '"cardNumber" "expiryDate" "securityCode" -docs -github',
        'intext:"4[0-9]{15}" "expir" -github -docs',  # Visa pattern
        'intext:"5[1-5][0-9]{14}" "expir" -github -docs',  # MC pattern
        'filetype:csv "card" "number" "expiry" "cvv"',
        'filetype:xls "credit card" "expires"',
        'filetype:xlsx "card number" "security code"',
        'filetype:csv "email" "password" "card"',
        
        # === PAYMENT GATEWAY KEYS ===
        'intext:"pk_live_" -"pk_live_test" -github -stackoverflow -stripe.com -docs',
        'intext:"pk_live_51" -github -docs -stripe.com',
        'intext:"pk_live_A" OR "pk_live_B" -github -docs',
        'intext:"sk_live_" -github -stackoverflow -stripe.com -bitbucket',
        'intext:"sk_live_51" -github -stripe.com',
        'intext:"rk_live_" -github -stripe.com',  # Restricted key
        'intext:"whsec_" -github -stripe.com',  # Webhook secret
        'intext:"pi_" "client_secret" -github -stripe.com',  # Payment intent
        'intext:"tok_" "card" -github -stripe.com',
        'intext:"AKIA" intext:"aws" -github -docs',
        'intext:"access_token" "bearer" filetype:json -github',
        'intext:"client_id" "client_secret" -github -docs -tutorial',
        'intext:"consumer_key" "consumer_secret" -github',
        'intext:"private_key" filetype:pem -github',
        'intext:"-----BEGIN RSA PRIVATE KEY-----" -github',
        
        # === PAYMENT PROCESSORS (NO CAPTCHA) ===
        'site:*.org intitle:donate intext:"pk_live_" -recaptcha -cloudflare',
        'site:*.org "donate now" intext:"stripe" -captcha',
        'site:*.church donate intext:"stripe" -cloudflare',
        'site:*.foundation "support" intext:"stripe" checkout',
        'site:*.charity intext:"pk_live_" donate',
        'site:*.ngo donate intext:"stripe" -captcha',
        '"make a donation" intext:"stripe" checkout -captcha',
        '"give now" intext:"pk_live_" -recaptcha',
        '"support us" intext:"stripe" payment -cloudflare',
        
        # === WOOCOMMERCE ===
        '"woocommerce" intext:"pk_live_" -github -docs',
        'inurl:checkout "woocommerce" intext:"stripe" -captcha',
        'intext:"wc_stripe_params" -github -stackoverflow',
        '"powered by woocommerce" intext:"stripe" -recaptcha',
        'site:*.shop woocommerce intext:"pk_live_"',
        'site:*.store woocommerce intext:"stripe"',
        
        # === SHOPIFY (SK KEYS) ===
        'intext:"shopify" "access_token" -github -docs',
        'intext:"X-Shopify-Access-Token" -github',
        '"shopify_api_key" -github -docs',
        'filetype:env "SHOPIFY_API" -github',
        
        # === BRAINTREE ===
        'intext:"braintree" "merchant_id" "public_key" "private_key" -github -docs',
        'intext:"braintree.client.create" -docs -github',
        '"data-braintree" checkout -github -docs',
        '"braintree_client_token" -github',
        'intext:"braintree" "sandbox" OR "production" "merchant" -docs -github',
        
        # === PAYPAL ===
        'intext:"paypal" "client_id" "secret" -github -docs',
        '"paypal checkout" intext:"client-id" -docs -github',
        '"PAYPAL_CLIENT_ID" "PAYPAL_SECRET" -github',
        'filetype:env "PAYPAL" -github',
        
        # === AUTHORIZE.NET ===
        'intext:"authorize.net" "api_login_id" "transaction_key" -github -docs',
        'intext:"AuthorizeNet" "loginID" -github -docs',
        '"x_login" "x_tran_key" -github -docs',
        
        # === SQUARE ===
        'intext:"squareup" "access_token" -github -docs',
        '"sq0atp-" -github -docs',  # Square access token prefix
        '"sq0csp-" -github -docs',  # Square OAuth secret prefix
        
        # === ADYEN ===
        'intext:"adyen" "api_key" -github -docs',
        '"x-api-key" "adyen" -github -docs',
        
        # === VPS/HOSTING (EASY TARGETS) ===
        '"vps hosting" checkout intext:"stripe" -docs',
        '"cloud hosting" payment intext:"pk_live_"',
        '"dedicated server" intext:"stripe" -github',
        '"web hosting" inurl:checkout intext:"stripe"',
        '"reseller hosting" payment intext:"stripe"',
        '"rdp" checkout intext:"stripe"',
        '"seedbox" payment intext:"stripe"',
        
        # === PROXY/VPN ===
        '"proxy" checkout intext:"stripe" -docs',
        '"private proxy" purchase intext:"pk_live_"',
        '"vpn service" payment intext:"stripe"',
        '"residential proxy" checkout intext:"stripe"',
        '"socks5" payment intext:"stripe"',
        
        # === SQL INJECTION TARGETS ===
        'inurl:"id=" "you have an error in your sql syntax"',
        'inurl:"cat=" "mysql_fetch"',
        'inurl:"page=" "warning" "mysql"',
        'inurl:"id=" "unclosed quotation"',
        'inurl:"id=" "ODBC" "driver"',
        'inurl:"id=" "syntax error"',
        'inurl:"product=" "mysql_num_rows"',
        'inurl:"item=" "pg_query"',
        'inurl:"news=" "supplied argument is not a valid MySQL"',
        'inurl:"article=" "mysql_fetch_assoc"',
        'inurl:"view=" "mysql_fetch_row"',
        'inurl:".php?id=" site:*(DE)',
        'inurl:".asp?id=" site:*(DE)',
        'inurl:".php?cat=" -github -docs',
        'inurl:".php?page=" -github -docs',
        'inurl:".php?product=" -github -docs',
        'inurl:".php?item=" -github',
        'inurl:".php?news=" -github',
        'inurl:".php?article=" -github',
        'inurl:".php?view=" -github',
        'inurl:".php?user=" -github',
        'inurl:".php?order=" -github',
        'inurl:".asp?id=" -github',
        'inurl:".aspx?id=" -github',
        'inurl:".jsp?id=" -github',
        'inurl:".cfm?id=" -github',
        
        # === CLOUD MISCONFIGS ===
        'site:s3.amazonaws.com "payment" OR "card" OR "billing"',
        'site:s3.amazonaws.com "backup" OR "dump" OR "export"',
        'site:blob.core.windows.net "payment" OR "customer"',
        'site:storage.googleapis.com "database" OR "backup"',
        'site:firebaseio.com "users" OR "payments" OR "orders"',
        'site:herokuapp.com "api" "key" -docs -github',
        
        # === INTERNATIONAL (LESS SECURITY) ===
        'site:*.co.uk "donate" intext:"stripe" -recaptcha',
        'site:*.com.au "checkout" intext:"stripe"',
        'site:*.ca "donate" intext:"pk_live_" -cloudflare',
        'site:*.eu payment intext:"stripe" -captcha',
        'site:*.de intext:"stripe" checkout -captcha',
        'site:*.fr intext:"pk_live_" -captcha',
        'site:*.nl intext:"stripe" betaling -captcha',
        'site:*.in intext:"stripe" payment -paytm',
        'site:*.br intext:"pk_live_" -captcha',
        'site:*.mx intext:"stripe" pago',
        'site:*.za intext:"stripe" payment',
        'site:*.nz intext:"pk_live_"',
        'site:*.ie intext:"stripe" donation',
        'site:*.se intext:"pk_live_"',
        'site:*.no intext:"stripe" betaling',
        'site:*.pl intext:"pk_live_" platnosc',
        'site:*.cz intext:"stripe" platba',
        'site:*.tr intext:"stripe" odeme',
        
        # === GIFT CARDS ===
        '"gift card" purchase intext:"stripe" -amazon -ebay',
        '"digital gift card" checkout intext:"pk_live_"',
        '"prepaid card" intext:"pk_live_" purchase',
        '"store credit" payment intext:"stripe"',
        
        # === GAMING/DIGITAL ===
        '"game server" payment intext:"stripe"',
        '"discord bot" checkout intext:"pk_live_"',
        '"minecraft" payment intext:"stripe" -docs',
        '"virtual currency" purchase intext:"pk_live_"',
        '"premium account" upgrade intext:"stripe"',
        
        # === SAAS/SOFTWARE ===
        '"api access" payment intext:"stripe" -docs',
        'inurl:pricing "free trial" intext:"pk_live_"',
        'inurl:billing checkout intext:"pk_live_"',
        '"premium features" upgrade intext:"stripe"',
        
        # === SMALL BIZ / LOW SECURITY ===
        '"yoga" donate intext:"stripe"',
        '"photograph" checkout intext:"pk_live_"',
        '"tutoring" payment intext:"stripe"',
        '"coaching" checkout intext:"pk_live_"',
        '"wedding" booking intext:"stripe"',
        '"fitness" membership intext:"pk_live_"',
        '"dance" classes payment intext:"stripe"',
        '"martial arts" checkout intext:"pk_live_"',
        '"art gallery" checkout intext:"pk_live_"',
        '"music lessons" payment intext:"stripe"',
        '"cleaning service" booking intext:"stripe"',
        '"handmade" shop intext:"stripe"',
        '"organic" shop intext:"stripe" -amazon',
        '"vintage" checkout intext:"pk_live_"',
        
        # === RAZORPAY (INDIA/GLOBAL) ===
        'intext:"rzp_live_" -github -docs -razorpay.com',
        'intext:"rzp_test_" -github -razorpay.com',
        '"razorpay" "key_id" -github -docs',
        '"razorpay" checkout intext:"rzp_live_" -docs',
        'site:*.in intext:"rzp_live_" payment',
        
        # === MOLLIE (EU) ===
        'intext:"mollie" "api_key" "live_" -github -docs',
        '"mollie" checkout intext:"live_" -docs -github',
        'site:*.nl "mollie" payment -github',
        'site:*.be "mollie" betaling -github',
        'site:*.de "mollie" zahlung -github',
        
        # === PAYU / PAYSTACK / FLUTTERWAVE (EMERGING MARKETS) ===
        'intext:"paystack" "pk_live_" -github -docs',
        'intext:"flutterwave" "FLWPUBK" -github -docs',
        'intext:"payu" "merchant_key" -github -docs',
        'site:*.ng intext:"paystack" payment',
        'site:*.za intext:"payfast" payment',
        'site:*.ke intext:"mpesa" payment',
        'site:*.gh intext:"paystack" checkout',
        
        # === CRYPTOCURRENCY PAYMENT ===
        'intext:"coinbase" "commerce" "api_key" -github -docs',
        'intext:"bitpay" "api_token" -github -docs',
        '"accept bitcoin" checkout intext:"stripe" OR "coinbase"',
        '"crypto payment" intext:"api_key" -github',
        'intext:"nowpayments" "api_key" -github',
        'intext:"coingate" "api_key" -github',
        
        # === SAAS / DIGITAL SERVICES ===
        '"software" subscription checkout intext:"pk_live_"',
        '"cloud" service pricing intext:"stripe" -aws -azure -gcp',
        '"api" pricing intext:"pk_live_" -docs -github',
        '"license key" purchase intext:"stripe"',
        '"seat" pricing intext:"pk_live_" -github',
        '"per user" pricing intext:"stripe" checkout',
        'inurl:"/subscribe" intext:"pk_live_"',
        'inurl:"/upgrade" intext:"pk_live_"',
        'inurl:"/billing" intext:"stripe" OR "pk_live_"',
        
        # === FOOD / RESTAURANT / DELIVERY ===
        '"restaurant" "order online" intext:"stripe" -github',
        '"food delivery" checkout intext:"pk_live_"',
        '"catering" payment intext:"stripe"',
        '"bakery" order intext:"pk_live_"',
        '"coffee" shop intext:"stripe" checkout',
        '"meal prep" order intext:"pk_live_"',
        '"meal kit" checkout intext:"stripe"',
        'inurl:"/order" "restaurant" intext:"pk_live_"',
        
        # === REAL ESTATE / PROPERTY ===
        '"property" payment intext:"stripe" -github',
        '"rent" payment intext:"pk_live_"',
        '"deposit" payment intext:"stripe" lease',
        '"hoa" payment intext:"pk_live_"',
        '"tenant" portal intext:"stripe" payment',
        '"landlord" payment intext:"pk_live_"',
        'inurl:"/pay-rent" intext:"stripe" OR "pk_live_"',
        
        # === AUTOMOTIVE ===
        '"auto parts" checkout intext:"pk_live_"',
        '"car" payment intext:"stripe" -github',
        '"vehicle" checkout intext:"pk_live_"',
        '"tire" shop intext:"stripe" checkout',
        '"detailing" booking intext:"pk_live_"',
        
        # === BEAUTY / WELLNESS ===
        '"salon" booking intext:"stripe"',
        '"spa" booking intext:"pk_live_"',
        '"cosmetics" checkout intext:"stripe"',
        '"skincare" shop intext:"pk_live_"',
        '"tattoo" deposit intext:"stripe"',
        '"nails" appointment intext:"pk_live_"',
        
        # === HEALTHCARE PAYMENT ===
        '"patient" payment intext:"stripe" -github',
        '"copay" payment intext:"pk_live_"',
        '"medical bill" pay intext:"stripe"',
        '"telehealth" payment intext:"pk_live_"',
        '"therapy" session intext:"stripe" payment',
        '"dental" payment intext:"pk_live_"',
        'inurl:"/patient-portal" intext:"stripe" OR "payment"',
        
        # === EDUCATION PAYMENT ===
        '"tuition" payment intext:"stripe" -github',
        '"course" enrollment intext:"pk_live_"',
        '"bootcamp" checkout intext:"stripe"',
        '"online class" payment intext:"pk_live_"',
        '"certificate" purchase intext:"stripe"',
        '"workshop" register intext:"pk_live_"',
        '"webinar" ticket intext:"stripe"',
        '"exam" registration payment intext:"pk_live_"',
        
        # === DATING / SOCIAL PREMIUM ===
        '"premium" membership intext:"stripe" -github -docs',
        '"vip" access intext:"pk_live_"',
        '"dating" premium intext:"stripe"',
        '"premium" upgrade intext:"pk_live_" -github',
        
        # === STREAMING / DIGITAL CONTENT ===
        '"streaming" subscription intext:"pk_live_"',
        '"podcast" support intext:"stripe"',
        '"video" subscription intext:"pk_live_"',
        '"ebook" purchase intext:"stripe"',
        '"digital download" checkout intext:"pk_live_"',
        '"audiobook" purchase intext:"stripe"',
        
        # === EVENT / TICKETING ===
        '"event" ticket intext:"stripe" -github',
        '"concert" ticket intext:"pk_live_"',
        '"festival" ticket intext:"stripe"',
        '"conference" registration intext:"pk_live_"',
        '"seminar" register intext:"stripe"',
        '"workshop" ticket intext:"pk_live_"',
        '"gala" ticket intext:"stripe"',
        'inurl:"/tickets" intext:"pk_live_"',
        'inurl:"/register" intext:"stripe" event',
        
        # === PET / VETERINARY ===
        '"pet" store intext:"pk_live_"',
        '"veterinary" payment intext:"stripe"',
        '"pet insurance" intext:"pk_live_"',
        '"dog grooming" intext:"stripe"',
        '"pet supplies" checkout intext:"pk_live_"',
        
        # === INSURANCE PAYMENT ===
        '"insurance" payment intext:"stripe" -github',
        '"premium" payment intext:"pk_live_" insurance',
        '"policy" payment intext:"stripe" -github',
        '"quote" intext:"pk_live_" insurance',
        
        # === LEGAL PAYMENT ===
        '"legal" payment intext:"stripe" -github',
        '"consultation" fee intext:"pk_live_"',
        '"retainer" payment intext:"stripe"',
        '"court filing" fee intext:"pk_live_"',
        
        # === TELECOM / UTILITY ===
        '"mobile" recharge intext:"stripe" -github',
        '"prepaid" topup intext:"pk_live_"',
        '"internet" bill intext:"stripe" pay',
        '"utility" payment intext:"pk_live_"',
        '"bill pay" intext:"stripe" -github',
        
        # === WEDDING / EVENT PLANNING ===
        '"wedding" deposit intext:"stripe"',
        '"wedding" registry intext:"pk_live_"',
        '"florist" order intext:"stripe"',
        '"photographer" booking intext:"pk_live_"',
        '"venue" deposit intext:"stripe"',
        '"planner" payment intext:"pk_live_"',
        
        # === PRINTING / CUSTOM ===
        '"custom" order intext:"stripe" checkout',
        '"printing" order intext:"pk_live_"',
        '"personalized" shop intext:"stripe"',
        '"embroidery" order intext:"pk_live_"',
        '"signs" order intext:"stripe" checkout',
        
        # === GIG ECONOMY ===
        '"freelance" payment intext:"stripe" -github',
        '"contractor" payment intext:"pk_live_"',
        '"invoice" pay intext:"stripe" -github',
        '"gig" payment intext:"pk_live_"',
        
        # === WHMCS / HOSTING BILLING ===
        'inurl:"whmcs" "clientarea" -demo -docs',
        'inurl:"whmcs/cart.php" -github -docs',
        'inurl:"hostbill" "payment" -github',
        'inurl:"blesta" "order" -github -docs',
        '"whmcs" intext:"stripe" OR "paypal" checkout',
        'intitle:"Client Area" "WHMCS" -demo',
        
        # === OPENCART / PRESTASHOP / MAGENTO ===
        '"powered by opencart" intext:"checkout" -github',
        'inurl:"index.php?route=checkout" -github -demo',
        '"prestashop" inurl:"order" -github -docs -demo',
        '"magento" inurl:"checkout" -github -docs -demo',
        'inurl:"onepage/checkout" "magento" -docs',
        
        # === EXPOSED API ENDPOINTS WITH PAYMENT ===
        'inurl:"/api/v1/" "payment" OR "charge" OR "invoice" -github',
        'inurl:"/api/v2/" "payment" OR "order" -github',
        'inurl:"/api/" "stripe" "secret" -github -docs',
        'inurl:"/api/" "card" "number" -github -docs',
        'inurl:"/graphql" "payment" OR "order" -github',
        'inurl:"/rest/V1/" "payment" magento -docs',
        
        # === JENKINS / CI-CD EXPOSED ===
        'intitle:"Dashboard [Jenkins]" -demo',
        'inurl:"/script" "Jenkins" "groovy" -github',
        'intitle:"GitLab" "sign_in" -gitlab.com',
        'inurl:"/.env" "STRIPE" OR "PAYPAL" OR "DB_PASSWORD"',
        
        # === FIREBASE / CLOUD DB EXPOSED ===
        'site:firebaseio.com "payment" OR "card" OR "order"',
        'site:firebaseio.com "user" "email" "password"',
        '"firebaseio.com" intext:".json" "payment"',
        'site:firestore.googleapis.com "payment"',
        
        # === GOOGLE SHEETS / DOCS EXPOSED ===
        'site:docs.google.com/spreadsheets "card" "cvv" OR "expiry"',
        'site:docs.google.com/spreadsheets "payment" "amount"',
        'site:docs.google.com/spreadsheets "password" "email"',
        'site:docs.google.com/spreadsheets "stripe" "key"',
        
        # === PASTEBIN / CODE SHARE ===
        'site:pastebin.com "sk_live_" OR "pk_live_"',
        'site:pastebin.com "DB_PASSWORD" OR "STRIPE_SECRET"',
        'site:justpaste.it "sk_live_" OR "api_key"',
        'site:dpaste.org "stripe" OR "paypal" "secret"',
        'site:hastebin.com "sk_live_" OR "AKIA"',
        
        # === TRELLO / NOTION EXPOSED ===
        'site:trello.com "stripe" "api" "key" OR "secret"',
        'site:trello.com "password" "database" OR "server"',
        'site:notion.so "api_key" OR "secret_key"',
        
        # === DEEP SQLi (ERROR MESSAGES) ===
        '"Warning: mysql_" inurl:".php?" site:*(DE)',
        '"Warning: pg_" inurl:".php?" site:*(DE)',
        '"ORA-" "error" inurl:".jsp?" site:*(DE)',
        '"Microsoft OLE DB Provider" inurl:".asp?" site:*(DE)',
        '"JDBC" "error" inurl:".jsp?" -github -docs',
        '"sqlite3.OperationalError" inurl:".py?" -github -docs',
        '"Unclosed quotation mark" inurl:".aspx?"',
        '"SQL syntax" "near" inurl:".php?"',
        '"supplied argument is not a valid MySQL result resource" inurl:".php?"',
        
        # === REGIONALIZED HIGH-VALUE (PAYMENT FOCUS) ===
        'site:*.edu "donate" intext:"stripe" -captcha',
        'site:*.edu "payment" intext:"pk_live_" -captcha',
        'site:*.gov "payment" intext:"stripe" -captcha',
        'site:*.gov "fee" intext:"pk_live_"',
        'site:*.mil "payment" OR "fee" -captcha',
        'site:*.org.uk "donate" intext:"stripe"',
        'site:*.org.au "donate" intext:"pk_live_"',
        'site:*.org.nz "donate" intext:"stripe"',
        'site:*.or.jp intext:"stripe" payment',
        'site:*.co.za intext:"payfast" OR "stripe"',
        'site:*.com.ng intext:"paystack" OR "flutterwave"',
        'site:*.co.ke intext:"mpesa" OR "stripe"',
        'site:*.com.br intext:"stripe" OR "pagseguro"',
        'site:*.com.mx intext:"stripe" OR "conekta"',
        'site:*.com.ar intext:"mercadopago" OR "stripe"',
        'site:*.co.il intext:"stripe" payment',
        'site:*.ae intext:"stripe" payment',
        'site:*.sg intext:"stripe" checkout',
        'site:*.hk intext:"stripe" payment',
        'site:*.ph intext:"stripe" OR "paymongo"',
        'site:*.my intext:"stripe" payment',
        'site:*.th intext:"stripe" OR "omise"',
        'site:*.vn intext:"stripe" payment',
        'site:*.id intext:"stripe" OR "midtrans"',
    ]

    def __init__(self, params_dir: str = None):
        """Initialize the dork generator.
        
        Args:
            params_dir: Directory containing keyword parameter files.
                        Defaults to ./params/ relative to this file.
        """
        if params_dir is None:
            params_dir = os.path.join(os.path.dirname(__file__), "params")
        
        self.params_dir = Path(params_dir)
        self.params: Dict[str, List[str]] = {}
        self.patterns = self.DEFAULT_PATTERNS.copy()
        
        # Load parameter files
        self._load_params()
        
        logger.info(f"DorkGenerator initialized: {len(self.patterns)} patterns, "
                    f"{sum(len(v) for v in self.params.values())} total keywords")

    def _load_params(self):
        """Load all parameter files from the params directory."""
        param_files = {
            "(KW)": "kw.txt",
            "(PT)": "pt.txt",
            "(PP)": "pp.txt",
            "(DE)": "de.txt",
            "(PF)": "pf.txt",
            "(SF)": "sf.txt",
        }
        
        for prefix, filename in param_files.items():
            filepath = self.params_dir / filename
            if filepath.exists():
                with open(filepath, "r") as f:
                    values = []
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#"):
                            values.append(line)
                    self.params[prefix] = values
                    logger.info(f"Loaded {len(values)} values for {prefix} from {filename}")
            else:
                self.params[prefix] = []
                logger.warning(f"Parameter file not found: {filepath}")

    def _get_prefixes_in_pattern(self, pattern: str) -> List[str]:
        """Extract which prefixes are used in a pattern."""
        prefixes = []
        for prefix in self.params:
            if prefix in pattern:
                prefixes.append(prefix)
        return prefixes

    def generate_from_pattern(self, pattern: str, max_per_pattern: int = 500) -> List[str]:
        """Generate dorks from a single pattern template.
        
        Args:
            pattern: Pattern template like '(KW).(PT)?(PP)='
            max_per_pattern: Max dorks to generate per pattern
            
        Returns:
            List of generated dork strings
        """
        prefixes = self._get_prefixes_in_pattern(pattern)
        if not prefixes:
            return [pattern]  # No substitution needed
        
        # Check all required params exist
        param_lists = []
        for prefix in prefixes:
            values = self.params.get(prefix, [])
            if not values:
                logger.warning(f"No values for {prefix}, skipping pattern: {pattern}")
                return []
            param_lists.append((prefix, values))
        
        # Calculate total combinations
        total = 1
        for _, values in param_lists:
            total *= len(values)
        
        dorks = []
        
        if total <= max_per_pattern:
            # Generate all combinations
            value_lists = [values for _, values in param_lists]
            for combo in itertools.product(*value_lists):
                dork = pattern
                for i, (prefix, _) in enumerate(param_lists):
                    dork = dork.replace(prefix, combo[i], 1)
                dorks.append(dork)
        else:
            # Random sampling to stay within limit
            seen = set()
            attempts = 0
            while len(dorks) < max_per_pattern and attempts < max_per_pattern * 3:
                combo = tuple(random.choice(values) for _, values in param_lists)
                if combo not in seen:
                    seen.add(combo)
                    dork = pattern
                    for i, (prefix, _) in enumerate(param_lists):
                        dork = dork.replace(prefix, combo[i], 1)
                    dorks.append(dork)
                attempts += 1
        
        return dorks

    def generate_all(self, max_total: int = 50000, max_per_pattern: int = 500) -> List[str]:
        """Generate all dorks from all patterns + static dorks.
        
        Args:
            max_total: Maximum total dorks to generate
            max_per_pattern: Maximum dorks per pattern
            
        Returns:
            Deduplicated list of dork queries
        """
        all_dorks: Set[str] = set()
        
        # Add static dorks first (high priority)
        for dork in self.STATIC_DORKS:
            all_dorks.add(dork)
        
        logger.info(f"Added {len(self.STATIC_DORKS)} static dorks")
        
        # Generate from patterns
        for pattern in self.patterns:
            if len(all_dorks) >= max_total:
                break
            generated = self.generate_from_pattern(pattern, max_per_pattern)
            for dork in generated:
                if len(all_dorks) >= max_total:
                    break
                all_dorks.add(dork)
        
        result = list(all_dorks)
        random.shuffle(result)
        
        logger.info(f"Generated {len(result)} total unique dorks "
                    f"({len(self.STATIC_DORKS)} static + {len(result) - len(self.STATIC_DORKS)} dynamic)")
        
        return result

    def generate_targeted(self, category: str, max_count: int = 500) -> List[str]:
        """Generate dorks targeting a specific category.
        
        Args:
            category: One of 'cards', 'gateways', 'secrets', 'sqli', 'databases', 'cloud'
            max_count: Maximum dorks to generate
            
        Returns:
            List of category-specific dorks
        """
        category_patterns = {
            "cards": [
                'intext:"card_number" "expiry" "cvv" site:*(DE)',
                'filetype:sql "credit_card" OR "cc_number"',
                'filetype:csv "card" "number" "expiry"',
                'intext:"4[0-9]{15}" OR "5[1-5][0-9]{14}" filetype:sql',
                '"cardNumber" "expiryDate" "securityCode" site:*(DE)',
                'intext:"pan_number" "expiration" site:*(DE)',
                '"INSERT INTO" "card" "number" filetype:sql',
                'intitle:"index of" "cards" ext:csv',
            ],
            "gateways": [
                'intext:"pk_live_" "(KW)" -github -docs',
                'intext:"stripe" checkout "(KW)" -captcha',
                'intext:"braintree" payment "(KW)" -github',
                'intext:"paypal" checkout "(KW)" -github',
                '"(KW)" donate intext:"stripe" site:*.org',
                '"(KW)" checkout intext:"pk_live_"',
            ],
            "secrets": [
                'filetype:env "(KW)" -github',
                '"(KW)" intext:"sk_live_" -github',
                '"(KW)" intext:"api_key" -github',
                '"(KW)" intext:"secret_key" -github',
                '"(KW)" intext:"AKIA" -github',
                '"(KW)" intext:"password" filetype:log',
                'intitle:"index of" "(KW)" ".env"',
            ],
            "sqli": [
                'inurl:"(KW)(PT)?(PP)="',
                'inurl:"(PP)=" "(KW)" ext:php',
                'inurl:"(PP)=" "(KW)" ext:asp',
                'site:*(DE) inurl:"(PT)?(PP)=" (KW)',
                'inurl:"(KW)" "sql syntax" OR "mysql_fetch"',
            ],
            "databases": [
                '"(KW)" site:s3.amazonaws.com',
                '"(KW)" intitle:"phpMyAdmin"',
                '"(KW)" intitle:"Adminer"',
                'intitle:"index of" "(KW)" "sql"',
                'intitle:"index of" "(KW)" "backup"',
                '"(KW)" inurl:phpmyadmin',
                '"(KW)" site:firebaseio.com',
            ],
            "cloud": [
                'site:s3.amazonaws.com "(KW)"',
                'site:blob.core.windows.net "(KW)"',
                'site:storage.googleapis.com "(KW)"',
                'site:firebaseio.com "(KW)"',
                '"(KW)" inurl:"amazonaws.com" -docs',
            ],
        }
        
        patterns = category_patterns.get(category, [])
        if not patterns:
            logger.warning(f"Unknown category: {category}")
            return []
        
        all_dorks: Set[str] = set()
        per_pattern = max(max_count // len(patterns), 10)
        
        for pattern in patterns:
            generated = self.generate_from_pattern(pattern, per_pattern)
            for dork in generated:
                if len(all_dorks) >= max_count:
                    break
                all_dorks.add(dork)
        
        result = list(all_dorks)
        random.shuffle(result)
        logger.info(f"Generated {len(result)} dorks for category '{category}'")
        return result

    def get_stats(self) -> Dict:
        """Get generator statistics."""
        total_possible = 1
        for prefix, values in self.params.items():
            if values:
                total_possible *= len(values)
        
        return {
            "patterns": len(self.patterns),
            "static_dorks": len(self.STATIC_DORKS),
            "param_counts": {k: len(v) for k, v in self.params.items()},
            "total_possible_combinations": total_possible,
            "categories": ["cards", "gateways", "secrets", "sqli", "databases", "cloud"],
        }
