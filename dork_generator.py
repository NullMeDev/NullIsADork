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
        
        # === Card data in URL/file patterns ===
        'inurl:"(PP)=" intext:"credit card" "(KW)" -github -docs',
        'inurl:"(PP)=" intext:"card_number" "(KW)" -github',
        'inurl:"(PP)=" intext:"cvv" "(KW)" -github -docs',
        '"(KW)" intext:"card_number" "expiry" -github -tutorial',
        '"(KW)" intext:"cc_number" "cvv" -github -docs',
        
        # === Payment processor credential patterns ===
        '"(KW)" intext:"rzp_live_" -github -razorpay.com',
        '"(KW)" intext:"sq0atp-" -github -docs',
        '"(KW)" intext:"FLWPUBK" -github -docs',
        '"(KW)" intext:"paystack" "pk_live_" -github',
        '"(KW)" intext:"mollie" "live_" -github',
        '"(KW)" intext:"conekta" "key_" -github',
        '"(KW)" intext:"midtrans" "server_key" -github',
        '"(KW)" intext:"omise" "pkey_" -github',
        '"(KW)" intext:"paymongo" "pk_live_" -github',
        '"(KW)" intext:"2checkout" "merchant_code" -github',
        '"(KW)" intext:"cybersource" "merchant_id" -github',
        '"(KW)" intext:"authorize.net" "transaction_key" -github',
        '"(KW)" intext:"worldpay" "installation_id" -github',
        '"(KW)" intext:"nmi" "security_key" -github',
        
        # === E-commerce platform patterns ===
        '"(KW)" inurl:"index.php?route=checkout" -demo',
        '"(KW)" inurl:"onepage/checkout" -docs -demo',
        '"(KW)" "woocommerce" intext:"pk_live_" -github',
        '"(KW)" "prestashop" inurl:order -github -demo',
        '"(KW)" "magento" inurl:checkout -github -demo',
        '"(KW)" "opencart" checkout -github -demo',
        '"(KW)" "zen cart" inurl:checkout -github',
        '"(KW)" "oscommerce" inurl:checkout -github',
        '"(KW)" "xcart" inurl:cart -github',
        
        # === Webhook / API endpoint patterns ===
        '"(KW)" inurl:"/api/" "payment" -github -docs',
        '"(KW)" inurl:"/webhook" "stripe" -github -docs',
        '"(KW)" inurl:"/api/" "charge" "card" -github',
        '"(KW)" inurl:"/rest/" "payment" "order" -github',
        '"(KW)" inurl:"/graphql" "payment" -github',
        
        # === POS / Terminal patterns ===
        '"(KW)" intitle:"POS" "terminal" -github -docs',
        '"(KW)" intext:"point of sale" inurl:login -github',
        '"(KW)" intext:"card reader" "payment" -github -docs',
        
        # === Subscription / Recurring billing patterns ===
        '"(KW)" inurl:"/subscribe" intext:"pk_live_" -github',
        '"(KW)" inurl:"/membership" intext:"stripe" -github',
        '"(KW)" inurl:"/upgrade" intext:"pk_live_" -github',
        '"(KW)" inurl:"/pricing" intext:"stripe" checkout',
        '"(KW)" "recurring" "billing" intext:"pk_live_" -github',
        
        # === Exposed backup / dump patterns ===
        '"(KW)" filetype:sql "INSERT INTO" "card" OR "payment"',
        '"(KW)" filetype:csv "card" "number" "expiry"',
        '"(KW)" filetype:xls "credit card" "expires"',
        '"(KW)" filetype:xlsx "card number" "security code"',
        '"(KW)" intitle:"index of" "payment" ext:sql',
        '"(KW)" intitle:"index of" "orders" ext:csv',
        
        # === Error-based SQLi with payment context ===
        'inurl:"(PF)(PT)?(PP)=" "(KW)" "checkout" "error"',
        'inurl:"(PP)=" "(KW)" "cart" intext:"mysql"',
        'inurl:"(PP)=" "(KW)" "order" intext:"sql syntax"',
        'inurl:"(PP)=" "(KW)" intext:"payment" "warning"',
        
        # === Cloud storage with payment data ===
        '"(KW)" site:s3.amazonaws.com "payment" OR "card"',
        '"(KW)" site:blob.core.windows.net "payment"',
        '"(KW)" site:storage.googleapis.com "payment"',
        '"(KW)" site:firebaseio.com "payment" OR "order"',
        
        # === WHMCS / Hosting billing ===
        '"(KW)" inurl:"whmcs" "clientarea" -demo',
        '"(KW)" inurl:"hostbill" payment -github',
        '"(KW)" inurl:"blesta" order -github',
        
        # === Authorize.net / Accept.js ===
        '"(KW)" intext:"apiLoginID" "clientKey" -github',
        '"(KW)" intext:"Accept.js" "authorize" -github',
        
        # === Nuvei / SafeCharge ===
        '"(KW)" intext:"SafeCharge" "merchantId" -github',
        '"(KW)" intext:"nuvei" "sessionToken" -github',
        
        # === BlueSnap ===
        '"(KW)" intext:"bluesnap" "data-bluesnap" -github',
        
        # === Paysafe ===
        '"(KW)" intext:"paysafe.checkout" -github',
        
        # === Opayo / Sage Pay ===
        '"(KW)" intext:"sagepay" "vendor" -github',
        
        # === Global Payments ===
        '"(KW)" intext:"GlobalPayments" "accessToken" -github',
        
        # === GoCardless ===
        '"(KW)" intext:"gocardless" "access_token" -github',
        
        # === Shift4 ===
        '"(KW)" intext:"shift4" "api_key" -github',
        
        # === Bambora ===
        '"(KW)" intext:"bambora" "merchant_id" -github',
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
        
        # === 2CHECKOUT / VERIFONE ===
        'intext:"2checkout" "seller_id" -github -docs',
        'intext:"2checkout" "secret_key" -github -docs',
        'intext:"2checkout" "merchant_code" "secret_key" -github',
        '"2checkout" intext:"INS_SECRET" -github',
        'filetype:env "TWOCHECKOUT" -github',
        
        # === CYBERSOURCE ===
        'intext:"cybersource" "access_key" "secret_key" -github -docs',
        'intext:"cybersource" "merchant_id" "transaction_key" -github',
        '"soap:cybersource" "merchant" -github -docs',
        'filetype:env "CYBERSOURCE" -github',
        
        # === FIRST DATA / FISERV ===
        'intext:"firstdata" "gateway_id" "password" -github -docs',
        'intext:"fiserv" "api_key" "api_secret" -github',
        '"payeezy" "api_key" "api_secret" -github -docs',
        'filetype:env "PAYEEZY" OR "FIRSTDATA" -github',
        
        # === CHASE PAYMENTECH ===
        'intext:"paymentech" "merchant_id" -github -docs',
        'intext:"chase" "paymentech" "orbital" -github',
        '"orbital" "merchant_id" "terminal_id" -github -docs',
        
        # === HEARTLAND / GLOBAL PAYMENTS ===
        'intext:"heartland" "secret_api_key" -github -docs',
        'intext:"globalpayments" "app_key" -github -docs',
        'intext:"realex" "merchant_id" "secret" -github -docs',
        '"heartland" "HPS" "secret" -github -docs',
        
        # === WEPAY ===
        'intext:"wepay" "client_id" "client_secret" -github -docs',
        'intext:"wepay" "access_token" -github -docs',
        'filetype:env "WEPAY" -github',
        
        # === RECURLY / CHARGEBEE / PADDLE ===
        'intext:"recurly" "api_key" -github -docs',
        'intext:"chargebee" "api_key" -github -docs',
        'intext:"paddle" "vendor_id" "vendor_auth_code" -github -docs',
        'intext:"fastspring" "api_username" "api_password" -github',
        'filetype:env "RECURLY" OR "CHARGEBEE" -github',
        'filetype:env "PADDLE_VENDOR" -github',
        
        # === GUMROAD / LEMONSQUEEZY ===
        'intext:"gumroad" "access_token" -github -docs',
        'intext:"lemonsqueezy" "api_key" -github -docs',
        '"gumroad" "seller_id" -github -docs',
        
        # === XENDIT (SEA) ===
        'intext:"xendit" "secret_key" -github -docs',
        'intext:"xendit" "xnd_" -github -docs',
        'site:*.id intext:"xendit" payment -github',
        'site:*.ph intext:"xendit" checkout -github',
        
        # === PESAPAL / DUSUPAY (AFRICA) ===
        'intext:"pesapal" "consumer_key" "consumer_secret" -github -docs',
        'intext:"dusupay" "api_key" -github -docs',
        'site:*.ug intext:"pesapal" payment',
        'site:*.tz intext:"pesapal" payment',
        'site:*.rw intext:"pesapal" OR "flutterwave"',
        
        # === KLARNA / AFTERPAY / AFFIRM ===
        'intext:"klarna" "api_key" -github -docs',
        'intext:"klarna" "merchant_id" "shared_secret" -github',
        'intext:"afterpay" "merchant_id" -github -docs',
        'intext:"affirm" "public_api_key" -github -docs',
        '"klarna" checkout intext:"api" -github -docs',
        'filetype:env "KLARNA" -github',
        'filetype:env "AFTERPAY" OR "AFFIRM" -github',
        
        # === MONERIS (CANADA) ===
        'intext:"moneris" "store_id" "api_token" -github -docs',
        'intext:"moneris" "hpp_key" -github -docs',
        'site:*.ca intext:"moneris" payment',
        
        # === EWAY (AUSTRALIA/NZ) ===
        'intext:"eway" "api_key" "password" -github -docs',
        'intext:"eway" "rapid" "api" -github -docs',
        'site:*.com.au intext:"eway" payment',
        'site:*.co.nz intext:"eway" checkout',
        
        # === PAGSEGURO / MERCADOPAGO (LATAM) ===
        'intext:"pagseguro" "token" -github -docs',
        'intext:"mercadopago" "access_token" -github -docs',
        'intext:"mercadopago" "public_key" -github -docs',
        '"MERCADOPAGO_ACCESS_TOKEN" -github',
        'filetype:env "PAGSEGURO" -github',
        
        # === CONEKTA (MEXICO) ===
        'intext:"conekta" "key_" -github -docs',
        'intext:"conekta" "private_key" -github',
        'site:*.com.mx intext:"conekta" payment',
        'filetype:env "CONEKTA" -github',
        
        # === IYZICO (TURKEY) ===
        'intext:"iyzico" "api_key" "secret_key" -github -docs',
        'intext:"iyzipay" "api_key" -github -docs',
        'site:*.com.tr intext:"iyzico" payment',
        
        # === POS / TERMINAL SYSTEMS ===
        'intitle:"POS" "terminal" inurl:login -demo',
        'intitle:"point of sale" "login" -github -docs',
        '"clover" intext:"access_token" -github -docs',
        '"square" "terminal" intext:"device_id" -github',
        'intext:"verifone" "terminal" inurl:admin',
        'intext:"ingenico" "terminal" inurl:login',
        '"lightspeed" pos intext:"api_key" -github -docs',
        '"toast" pos intext:"access_token" -github',
        '"shopkeep" inurl:login -docs',
        '"revel" pos intext:"api" -github -docs',
        
        # === CARD DATA IN SPREADSHEETS / DOCS ===
        'site:docs.google.com/spreadsheets "card number" "cvv" "expiry"',
        'site:docs.google.com/spreadsheets "credit card" "cvc"',
        'site:docs.google.com/spreadsheets "billing" "card" "amount"',
        'site:docs.google.com/spreadsheets "transaction" "card" "merchant"',
        'site:docs.google.com/spreadsheets "payment" "method" "card"',
        'site:docs.google.com/document "card_number" "expiry"',
        'site:docs.google.com/document "sk_live_" OR "pk_live_"',
        
        # === JIRA / CONFLUENCE / WIKI EXPOSED ===
        'site:*.atlassian.net "stripe" "api" "key"',
        'site:*.atlassian.net "payment" "credentials"',
        'inurl:"confluence" "stripe" "secret" -atlassian.com',
        'inurl:"jira" "payment" "api_key" -atlassian.com',
        
        # === GITLAB / BITBUCKET EXPOSED CONFIGS ===
        'site:gitlab.com "sk_live_" OR "pk_live_" -stripe.com',
        'site:bitbucket.org "sk_live_" -stripe.com',
        'site:gitlab.com filetype:env "STRIPE" OR "PAYPAL"',
        'site:gitlab.com "BRAINTREE_PRIVATE_KEY" OR "BRAINTREE_MERCHANT"',
        
        # === EXPOSED DOCKER / K8S CONFIGS ===
        'filetype:yml "STRIPE_SECRET_KEY" -github',
        'filetype:yml "PAYPAL_SECRET" -github',
        'filetype:yaml "api_key" "payment" -github',
        '"docker-compose" intext:"STRIPE_KEY" -github',
        '"docker-compose" intext:"PAYPAL" -github',
        'filetype:yml "kubernetes" "secret" "payment" -github',
        
        # === HEROKU / VERCEL / NETLIFY EXPOSED ===
        'site:herokuapp.com intext:"pk_live_" -github',
        'site:herokuapp.com "payment" inurl:"/api/" -github',
        'site:vercel.app intext:"pk_live_" -github',
        'site:netlify.app intext:"pk_live_" -github',
        'site:railway.app intext:"stripe" payment',
        'site:render.com intext:"stripe" checkout',
        
        # === AWS / GCP / AZURE EXPOSED ===
        'site:s3.amazonaws.com "credit_card" OR "card_number"',
        'site:s3.amazonaws.com filetype:sql "payment"',
        'site:s3.amazonaws.com filetype:csv "card" "cvv"',
        'site:s3.amazonaws.com ".env" "STRIPE"',
        'site:blob.core.windows.net "card" OR "payment" filetype:csv',
        'site:blob.core.windows.net filetype:sql "INSERT" "card"',
        'site:storage.googleapis.com "card" "payment" filetype:csv',
        'site:storage.googleapis.com filetype:sql "credit"',
        
        # === EXPOSED JUPYTER / NOTEBOOK ===
        'intitle:"Jupyter Notebook" intext:"payment" OR "stripe"',
        'intitle:"Jupyter" intext:"sk_live_" OR "pk_live_"',
        'inurl:"/notebooks/" "payment" "card" -github',
        
        # === CMS PAYMENT PLUGINS ===
        '"gravity forms" intext:"stripe" payment -github -docs',
        '"ninja forms" intext:"stripe" payment -github',
        '"formidable" intext:"pk_live_" -github -docs',
        '"caldera forms" intext:"stripe" -github',
        '"wpforms" intext:"stripe" -github -docs',
        '"give" intext:"pk_live_" donation -github -docs',
        '"charitable" donation intext:"stripe" -github',
        '"memberpress" intext:"pk_live_" -github -docs',
        '"restrict content pro" intext:"stripe" -github',
        '"paid memberships pro" intext:"pk_live_" -github',
        '"easy digital downloads" intext:"stripe" -github -docs',
        '"surecart" intext:"stripe" -github',
        
        # === LARAVEL / DJANGO / RAILS EXPOSED ===
        'inurl:".env" "STRIPE_SECRET" -github -gitlab -bitbucket',
        'inurl:".env" "PAYPAL_CLIENT_SECRET" -github -gitlab',
        'inurl:"settings.py" "STRIPE_SECRET_KEY" -github',
        'inurl:"config/secrets.yml" "stripe" -github',
        'inurl:"config/credentials" "stripe" -github',
        'inurl:".env.production" "STRIPE" OR "PAYPAL" -github',
        'inurl:".env.local" "STRIPE" OR "PAYPAL" -github',
        
        # === DEEP CARD PATTERN DORKS ===
        'intext:"4[0-9]{3}" "expir" "cvv" -github -docs',
        'intext:"5[1-5][0-9]{2}" "expir" "cvv" -github -docs',
        'intext:"3[47][0-9]{2}" "expir" "cvv" -github -docs',  # Amex
        'intext:"6011" "expir" "cvv" -github -docs',  # Discover
        'intext:"card" "4111111" -github -docs -test -example',
        'intext:"card" "5500000" -github -docs -test -example',
        
        # === INVOICE / RECEIPT EXPOSURE ===
        'intitle:"index of" "invoice" ext:pdf',
        'intitle:"index of" "receipt" ext:pdf',
        'intitle:"index of" "payment" ext:pdf',
        'inurl:"/invoices/" filetype:pdf -github',
        'inurl:"/receipts/" filetype:pdf -github',
        '"invoice" "paid" "card ending" filetype:pdf',
        '"receipt" "Visa" OR "Mastercard" filetype:pdf',
        
        # === MONGODB / NOSQL EXPOSED ===
        'inurl:":27017" "payment" OR "card"',
        'inurl:":27017" "customer" "credit"',
        'inurl:":5984" "payment" OR "billing"',  # CouchDB
        '"MongoDB" intext:"payment" "collection" -docs',
        'intitle:"mongo express" "payment" OR "order"',
        
        # === ELASTICSEARCH EXPOSED ===
        'inurl:":9200/_cat" "payment" OR "order"',
        'inurl:":9200" "card" "payment" -docs',
        'intitle:"Kibana" "payment" OR "transaction"',
        'inurl:":5601" "payment" OR "card" dashboard',
        
        # === GRAPHQL EXPOSED ===
        'inurl:"/graphql" "payment" "mutation" -github',
        'inurl:"/graphql" "card" "charge" -github',
        'inurl:"/graphiql" "payment" OR "order" -github',
        'intitle:"GraphQL Playground" "payment" -github',
        'intitle:"GraphiQL" "payment" OR "checkout" -github',
        
        # === SWAGGER / API DOCS EXPOSED ===
        'inurl:"/swagger" "payment" OR "checkout" -github',
        'inurl:"/api-docs" "payment" "charge" -github',
        'intitle:"Swagger UI" "payment" OR "card" -github',
        'inurl:"/redoc" "payment" OR "billing" -github',
        'inurl:"/openapi" "payment" -github',
        
        # === ADDITIONAL INJECTABLE CHECKOUT URLs ===
        'inurl:"checkout.php?cartid=" -github',
        'inurl:"checkout.php?UserID=" -github',
        'inurl:"checkout_confirmed.php?order_id=" -github',
        'inurl:"cart.php?action=" -github',
        'inurl:"cart_additem.php?id=" -github',
        'inurl:"product_details.php?product_id=" -github',
        'inurl:"product-list.php?category_id=" -github',
        'inurl:"proddetail.php?prod=" -github',
        'inurl:"shop_detail.php?id=" -github',
        'inurl:"comersus_viewItem.php?idProduct=" -github',
        'inurl:"eshop.php?id=" -github',
        'inurl:"estore/products.php?cat=" -github',
        'inurl:"buy.php?category=" -github',
        'inurl:"order.php?id=" -github',
        'inurl:"purchase.php?id=" -github',
        'inurl:"payment.php?id=" -github',
        'inurl:"billing.php?id=" -github',
        'inurl:"store.php?cat=" -github',
        'inurl:"shop.php?cat=" -github',
        'inurl:"catalog.php?CatalogID=" -github',
        'inurl:"viewcart.php?CartId=" -github',
        'inurl:"shoppingcart.php?id=" -github',
        'inurl:"getitem.php?id=" -github',
        
        # === ADDITIONAL ERROR-BASED SQLI ===
        '"Warning: mysql_" inurl:"checkout"',
        '"Warning: mysql_" inurl:"payment"',
        '"Warning: mysql_" inurl:"order.php"',
        '"Warning: mysql_" inurl:"cart.php"',
        '"SQL syntax" inurl:"product.php"',
        '"SQL syntax" inurl:"store.php"',
        '"SQL syntax" inurl:"shop.php"',
        '"ODBC" "driver" inurl:"checkout"',
        '"Unclosed quotation" inurl:"payment"',
        'inurl:".php?id=" "major credit cards accepted"',
        'inurl:".asp?id=" "major credit cards accepted"',
        'inurl:".php?id=" intext:"we accept visa" OR "mastercard"',
        
        # === MEMBERSHIP / SaaS BILLING ===
        '"stripe billing portal" -docs -github',
        '"customer_portal" intext:"stripe" -github -docs',
        '"billing_portal" intext:"pk_live_" -github',
        '"subscription_data" intext:"stripe" -github',
        'inurl:"/customer-portal" intext:"stripe"',
        'inurl:"/billing-portal" intext:"pk_live_"',
        
        # === SPECIFIC INDUSTRY HIGH-VALUE ===
        '"cannabis" checkout intext:"stripe" -github',
        '"cbd" payment intext:"pk_live_" -github',
        '"vape" checkout intext:"stripe" -github',
        '"supplements" checkout intext:"pk_live_"',
        '"kratom" payment intext:"stripe"',
        '"nootropics" checkout intext:"pk_live_"',
        '"adult" checkout intext:"stripe" -github',
        '"gambling" deposit intext:"stripe" -github',
        '"forex" payment intext:"pk_live_" -github',
        '"trading" subscription intext:"stripe" -github',
        '"crypto exchange" intext:"pk_live_" -github',
        '"nft" mint intext:"stripe" -github',
        '"dropshipping" checkout intext:"pk_live_"',
        '"print on demand" checkout intext:"stripe"',
        '"fulfillment" payment intext:"pk_live_"',
        
        # === GOVERNMENT / MUNICIPAL PAYMENTS ===
        'site:*.gov "pay" "fee" intext:"stripe" -captcha',
        'site:*.gov "permit" payment intext:"pk_live_"',
        'site:*.gov "license" fee intext:"stripe"',
        'site:*.gov.uk "pay" intext:"stripe"',
        'site:*.gc.ca "payment" intext:"stripe"',
        'site:*.gov.au "fee" intext:"stripe" payment',
        
        # === RELIGIOUS / NONPROFIT HIGH-VALUE ===
        'site:*.church "give" intext:"pk_live_" -captcha',
        'site:*.church "tithe" intext:"stripe" -captcha',
        'site:*.church "offering" intext:"pk_live_"',
        'site:*.org "donate" "monthly" intext:"pk_live_" -captcha',
        'site:*.org "contribute" intext:"stripe" -recaptcha',
        '"synagogue" donate intext:"pk_live_" -captcha',
        '"mosque" donate intext:"stripe" -captcha',
        '"temple" donate intext:"pk_live_" -captcha',
        '"ministry" give intext:"stripe" -captcha',
        '"parish" donate intext:"pk_live_"',
        '"diocese" payment intext:"stripe"',
        
        # === SCHOOL / UNIVERSITY FEES ===
        'site:*.edu "pay" "fee" intext:"stripe"',
        'site:*.edu "tuition" intext:"pk_live_"',
        'site:*.edu "application fee" intext:"stripe"',
        'site:*.edu "dining" payment intext:"pk_live_"',
        'site:*.edu "parking" permit intext:"stripe"',
        'site:*.edu "store" checkout intext:"pk_live_"',
        'site:*.ac.uk "fee" payment intext:"stripe"',
        'site:*.edu.au "payment" intext:"pk_live_"',
        
        # === EXPOSED PAYMENT LOGS ===
        'filetype:log "payment" "card" "approved" -github',
        'filetype:log "transaction" "amount" "card" -github',
        'filetype:log "charge" "stripe" "succeeded" -github',
        'filetype:log "PaymentIntent" "succeeded" -github',
        'filetype:log "authorize" "capture" "card" -github',
        'filetype:log "refund" "card_ending" -github',
        
        # === EXPOSED PAYMENT SQL DUMPS ===
        'filetype:sql "INSERT INTO" "orders" "card" "amount"',
        'filetype:sql "INSERT INTO" "transactions" "card_type"',
        'filetype:sql "INSERT INTO" "billing" "card_number"',
        'filetype:sql "CREATE TABLE" "payment_methods"',
        'filetype:sql "CREATE TABLE" "transactions" "card"',
        'filetype:sql "CREATE TABLE" "orders" "billing"',
        'filetype:sql "INSERT INTO" "customers" "credit_card"',
        'filetype:sql "INSERT INTO" "payments" "stripe"',
        
        # === EXPOSED STRIPE DASHBOARD / WEBHOOKS ===
        'inurl:"stripe.com/test_" -stripe.com',
        'inurl:"/stripe/webhook" -github -docs',
        'inurl:"/webhooks/stripe" -github -docs',
        'inurl:"/api/stripe" -github -docs',
        'inurl:"/stripe-webhook" -github -docs',
        'intext:"whsec_" -github -stripe.com -docs',
        'intext:"evt_" "payment_intent" -github -stripe.com',
        
        # === BIG COMMERCE / VOLUSION / 3DCART ===
        '"bigcommerce" intext:"client_id" "access_token" -github -docs',
        '"volusion" "api_key" -github -docs',
        '"3dcart" "api_key" -github -docs',
        'inurl:"bigcommerce.com" "checkout" intext:"pk_live_"',
        '"shift4shop" "api" intext:"key" -github',
        
        # === ECWID ===
        'intext:"ecwid" "store_id" -github -docs',
        '"app.ecwid.com" intext:"api" -docs',
        'inurl:"ecwid" checkout -demo -docs',
        
        # === SNIPCART / FOXY.IO / GUMROAD ===
        'intext:"snipcart" "api_key" -github -docs',
        '"snipcart" intext:"pk_" -github',
        '"foxy.io" intext:"store" -github -docs',
        
        # === PAYMENT FORM PAGES (NO SECURITY) ===
        '"enter your card" "card number" "expiry" -recaptcha -cloudflare -github',
        '"credit card information" "card number" "cvv" -docs -github -tutorial',
        '"billing information" "card number" intext:"pk_live_" -github',
        '"payment details" "card number" "security code" -github -docs',
        '"pay securely" intext:"pk_live_" -docs -github',
        '"secure checkout" intext:"pk_live_" -stripe.com -docs',
        
        # === MARKET-SPECIFIC PAYMENT GATEWAYS ===
        # Japan
        'site:*.jp intext:"stripe" payment',
        'site:*.jp intext:"payjp" "api_key" -github',
        '"payjp" "pk_" -github -docs',
        # South Korea
        'site:*.co.kr intext:"iamport" OR "toss" payment',
        '"iamport" intext:"api_key" -github',
        '"toss" "payments" "secret_key" -github -docs',
        # China
        '"wechat pay" "mch_id" "api_key" -github -docs',
        '"alipay" "app_id" "private_key" -github -docs',
        # Russia/CIS
        'site:*.ru intext:"yookassa" OR "robokassa" payment',
        '"yookassa" "shopId" "secret_key" -github',
        '"robokassa" "MerchantLogin" -github',
        # Middle East
        'site:*.ae intext:"telr" OR "payfort" payment',
        '"payfort" "access_code" "merchant_identifier" -github',
        '"tap" "payment" intext:"sk_live_" -github -stripe.com',
        '"hyperpay" intext:"entity_id" -github -docs',
        # Southeast Asia
        '"omise" intext:"pkey_live_" -github -docs',
        '"omise" intext:"skey_live_" -github -docs',
        '"paymaya" intext:"pk-" -github -docs',
        '"gcash" "api_key" -github -docs',
        '"grab pay" "merchant_id" -github -docs',
        
        # ========== STRIPE EXPANDED (SetupIntent, PaymentIntent, Elements) ==========
        'intext:"stripe.elements" -github -docs -stackoverflow -stripe.com',
        'intext:"stripe.confirmPayment" -github -docs -stripe.com',
        'intext:"stripe.confirmSetup" -github -docs -stripe.com',
        'intext:"stripe.confirmCardPayment" -github -docs -stripe.com',
        'intext:"stripe.createPaymentMethod" -github -docs -stripe.com',
        'intext:"stripe.createToken" -github -docs -stripe.com',
        'intext:"PaymentElement" "stripe" -github -docs -stripe.com',
        'intext:"CardElement" "stripe" -github -docs -stripe.com',
        'intext:"SetupIntent" "client_secret" -github -docs -stripe.com',
        'intext:"PaymentIntent" "client_secret" -github -docs -stripe.com',
        'intext:"pi_" "secret" "stripe" -github -stripe.com -docs',
        'intext:"seti_" "secret" "stripe" -github -stripe.com -docs',
        'intext:"cs_live_" -github -stripe.com -docs',  # Checkout session live
        'intext:"price_" "stripe" "live" -github -stripe.com -docs',
        'intext:"prod_" "stripe" "live" -github -stripe.com -docs',
        'intext:"sub_" "stripe" "customer" -github -stripe.com -docs',
        'intext:"cus_" "stripe" -github -stripe.com -docs',
        'intext:"pm_" "stripe" "card" -github -stripe.com -docs',
        'intext:"ch_" "stripe" "amount" -github -stripe.com -docs',
        'intext:"in_" "stripe" "invoice" -github -stripe.com -docs',
        '"data-stripe" "publishable" -github -docs -stripe.com',
        'intext:"Stripe.js" "pk_live_" -github -stripe.com -docs',
        'inurl:"/js/stripe" "pk_live_" -github -stripe.com',
        'intext:"loadStripe" "pk_live_" -github -docs -stripe.com',
        'intext:"@stripe/stripe-js" "pk_live_" -github -npm -docs',
        'intext:"stripe_publishable_key" -github -docs',
        'intext:"STRIPE_PUBLISHABLE" -github -docs -gitlab',
        'intext:"NEXT_PUBLIC_STRIPE" -github -docs',
        'intext:"REACT_APP_STRIPE" -github -docs',
        'intext:"VUE_APP_STRIPE" -github -docs',
        'intext:"GATSBY_STRIPE" -github -docs',
        'intext:"NUXT_STRIPE" OR "NUXT_PUBLIC_STRIPE" -github -docs',
        'intext:"stripe.redirectToCheckout" -github -docs -stripe.com',
        'intext:"stripe.handleCardAction" -github -docs -stripe.com',
        
        # ========== BRAINTREE EXPANDED (Auth Fingerprint, Drop-in, Hosted Fields, GraphQL) ==========
        'intext:"braintree.dropin.create" -github -docs -braintree.com',
        'intext:"braintree-web-drop-in" -github -npm -docs',
        'intext:"braintree.hostedFields.create" -github -docs -braintree.com',
        'intext:"braintree-hosted-field" -github -docs',
        'intext:"braintree.client.create" -github -docs -braintree.com',
        'intext:"auth_fingerprint" "braintree" -github -docs',
        'intext:"authorizationFingerprint" -github -docs -braintree.com',
        'intext:"client_token" "braintree" -github -docs -braintree.com',
        'intext:"tokenization_key" "braintree" -github -docs',
        'intext:"payment_method_nonce" "braintree" -github -docs',
        'intext:"braintree-web" "client" "create" -github -npm',
        'intext:"braintreeGateway" "merchantId" -github -docs',
        'intext:"Braintree.Configuration" "MerchantId" -github -docs',
        'intext:"new BraintreeGateway" -github -docs',
        'intext:"braintree_merchant_id" -github -docs',
        'intext:"BRAINTREE_TOKENIZATION_KEY" -github -docs',
        'intext:"BRAINTREE_MERCHANT_ID" "BRAINTREE_PUBLIC_KEY" -github',
        'inurl:"/braintree/graphql" -braintree.com -github',
        'inurl:"/client_api/v1/payment_methods" "braintree" -github',
        'intext:"data-braintree-name" -github -docs',
        'intext:"braintree_transaction_sale" -github -docs',
        'intext:"Braintree_Transaction::sale" -github -docs',
        'intext:"Braintree::Transaction.sale" -github -docs',
        'intext:"BraintreeDropIn" -github -docs -npm',
        'intext:"payment-method-nonce" "braintree" -github -docs',
        'intext:"braintree" "sandbox_" OR "production_" "merchant" -github -docs',
        'filetype:env "BRAINTREE_TOKENIZATION" -github',
        'filetype:env "BRAINTREE_ENVIRONMENT" "production" -github',
        'intext:"braintree.Environment.Production" -github -docs',
        
        # ========== PAYPAL PPCP (Commerce Platform) ==========
        'intext:"paypal.Buttons" "createOrder" -github -docs -paypal.com',
        'intext:"paypal-commerce-platform" -github -docs -paypal.com',
        'intext:"partner_merchant_id" "paypal" -github -docs',
        'intext:"BN-Code" "paypal" -github -docs',
        'intext:"paypal-js" "client-id" -github -npm -docs',
        'intext:"@paypal/react-paypal-js" -github -npm -docs',
        'intext:"paypal.FUNDING" -github -docs -paypal.com',
        'intext:"data-partner-attribution-id" "paypal" -github',
        'intext:"PAYPAL_CLIENT_ID" intext:"PAYPAL_CLIENT_SECRET" -github',
        'intext:"paypal_client_id" "paypal_secret" -github -docs',
        'intext:"PAYPAL_MERCHANT_ID" -github -docs',
        'intext:"paypal.Buttons" "fundingSource" -github -docs',
        'intext:"onApprove" "paypal" "orderID" -github -docs',
        'intext:"capture" "paypal" "orderID" -github -docs -paypal.com',
        'intext:"paypal-checkout" "data-merchant-id" -github -docs',
        
        # ========== ELAVON / CONVERGE ==========
        'intext:"elavon" "ssl_merchant_id" -github -docs',
        'intext:"converge" "ssl_merchant_id" -github -docs',
        'intext:"ssl_merchant_id" "ssl_user_id" "ssl_pin" -github -docs',
        'intext:"ssl_merchant_id" "ssl_transaction_type" -github -docs',
        'intext:"converge" "merchant_id" "user_id" -github -docs',
        '"elavon" "converge" intext:"api" -github -docs',
        'filetype:env "CONVERGE" OR "ELAVON" -github',
        'intext:"elavon" "hosted payments" -github -docs',
        'inurl:"/api/transact.do" "ssl_merchant" -github',
        'intext:"converge" "payment" site:*.com -elavon.com -github',
        
        # ========== NMI EXPANDED ==========
        'intext:"nmi" "security_key" "type=sale" -github -docs',
        'intext:"nmi" "username" "password" inurl:"api" -github -docs',
        'intext:"nmi_security_key" -github -docs',
        'intext:"NMI_SECURITY_KEY" -github -docs',
        'intext:"collect.js" "nmi" -github -docs',
        'intext:"CollectJS" "configure" -github -docs',
        'intext:"gateway_id" "nmi" -github -docs',
        'filetype:env "NMI_" -github',
        'inurl:"/api/transact" "security_key" "ccnumber" -github',
        'intext:"nmi" "three-step" "redirect" payment -github -docs',
        
        # ========== ADYEN EXPANDED ==========
        'intext:"adyen" "merchantAccount" -github -docs -adyen.com',
        'intext:"adyen-checkout" -github -npm -docs -adyen.com',
        'intext:"AdyenCheckout" "clientKey" -github -docs -adyen.com',
        'intext:"adyen" "originKey" -github -docs -adyen.com',
        'intext:"ADYEN_API_KEY" "ADYEN_MERCHANT" -github',
        'intext:"adyen" "live_" "api_key" -github -docs',
        'intext:"adyen" "/checkout/v" "payments" -github -docs',
        'intext:"adyen-encrypted-data" -github -docs',
        'intext:"adyen.encrypt" -github -docs -adyen.com',
        
        # ========== CHECKOUT.COM EXPANDED ==========
        'intext:"checkout.com" "secret_key" -github -docs -checkout.com',
        'intext:"checkout.com" "public_key" "pk_" -github -docs',
        'intext:"Frames" "checkout.com" -github -docs -checkout.com',
        'intext:"cko-" "checkout.com" -github -docs',
        'intext:"CKO_SECRET_KEY" -github -docs',
        'intext:"CHECKOUT_SECRET_KEY" -github -docs',
        
        # ========== WORLDPAY EXPANDED ==========
        'intext:"worldpay" "installation_id" "merchant_code" -github -docs',
        'intext:"worldpay" "service_key" -github -docs -worldpay.com',
        'intext:"worldpay" "client_key" -github -docs -worldpay.com',
        'intext:"WORLDPAY_SERVICE_KEY" -github -docs',
        'intext:"WORLDPAY_MERCHANT_CODE" -github -docs',
        'intext:"worldpay.js" -github -docs -worldpay.com',
        
        # ========== CYBERSOURCE EXPANDED ==========
        'intext:"cybersource" "access_key" "profile_id" -github -docs',
        'intext:"cybersource" "transaction_uuid" -github -docs',
        'intext:"CyberSource.Client" "merchantId" -github -docs',
        'intext:"CYBERSOURCE_ACCESS_KEY" OR "CYBERSOURCE_PROFILE_ID" -github',
        'intext:"cybersource" "flex" "microform" -github -docs',
        'intext:"cybersource" "secure_acceptance" -github -docs',
        
        # ========== MONERIS EXPANDED ==========
        'intext:"moneris" "ps_store_id" "hpp_key" -github -docs',
        'intext:"moneris" "api_token" "store_id" -github -docs -moneris.com',
        'intext:"MONERIS_STORE_ID" "MONERIS_API_TOKEN" -github',
        'intext:"moneris" "hosted_tokenization" -github -docs',
        'intext:"moneris" "checkout_id" -github -docs',
        
        # ========== RECURLY / CHARGEBEE / PADDLE EXPANDED ==========
        'intext:"recurly.configure" -github -docs -recurly.com',
        'intext:"recurly" "public_key" -github -docs -recurly.com',
        'intext:"RECURLY_PUBLIC_KEY" -github -docs',
        'intext:"recurly-elements" -github -docs',
        'intext:"chargebee.init" "site" -github -docs -chargebee.com',
        'intext:"CHARGEBEE_SITE" "CHARGEBEE_API_KEY" -github',
        'intext:"chargebee" "cbInstance" -github -docs -chargebee.com',
        'intext:"Paddle.Setup" -github -docs -paddle.com',
        'intext:"Paddle.Checkout.open" -github -docs -paddle.com',
        'intext:"PADDLE_VENDOR_ID" "PADDLE_VENDOR_AUTH" -github',
        
        # ========== WOOCOMMERCE NON-STRIPE GATEWAYS ==========
        '"woocommerce" intext:"braintree" "merchant_id" -github -docs',
        '"woocommerce" intext:"authorize_net" "api_login" -github -docs',
        '"woocommerce" intext:"nmi" "security_key" -github -docs',
        '"woocommerce" intext:"square" "access_token" -github -docs',
        '"woocommerce" intext:"paypal" "client_id" "secret" -github -docs',
        '"woocommerce" "elavon" "converge" -github -docs',
        '"woocommerce" "adyen" "api_key" -github -docs',
        '"woocommerce" "worldpay" -github -docs',
        
        # ========== .ENV FILES WITH PAYMENT KEYS (EXPANDED) ==========
        'filetype:env "STRIPE_SECRET_KEY" "STRIPE_PUBLISHABLE" -github -gitlab',
        'filetype:env "BRAINTREE_MERCHANT_ID" "BRAINTREE_PRIVATE" -github',
        'filetype:env "PAYPAL_CLIENT_ID" "PAYPAL_SECRET" -github -gitlab',
        'filetype:env "ADYEN_API_KEY" -github -gitlab',
        'filetype:env "NMI_SECURITY_KEY" -github -gitlab',
        'filetype:env "SQUARE_ACCESS_TOKEN" -github -gitlab',
        'filetype:env "AUTHORIZE_NET" OR "AUTHORIZENET" -github -gitlab',
        'filetype:env "ELAVON" OR "CONVERGE_MERCHANT" -github',
        'filetype:env "CHECKOUT_SECRET" OR "CKO_SECRET" -github',
        'filetype:env "WORLDPAY" OR "CYBERSOURCE" -github -gitlab',
        'filetype:env "MONERIS_API" OR "MONERIS_STORE" -github',
        'filetype:env "RECURLY_API" OR "CHARGEBEE_API" -github',
        'filetype:env "PADDLE_VENDOR" OR "PADDLE_API" -github',
        'inurl:".env.production" "STRIPE_SECRET" -github -gitlab',
        'inurl:".env.production" "BRAINTREE" OR "PAYPAL_SECRET" -github',
        'inurl:".env.local" "STRIPE_SECRET" OR "PAYPAL_SECRET" -github',
        
        # ========== JS BUNDLE / SOURCE MAP KEY LEAKS ==========
        'filetype:js "pk_live_" -github -npm -cdn.stripe.com',
        'filetype:js "sk_live_" -github -npm -stripe.com',
        'filetype:js "rzp_live_" -github -npm',
        'filetype:js "sq0atp-" -github -npm',
        'filetype:js "AKIA" "AWS" -github -npm',
        'filetype:js "client_id" "client_secret" "paypal" -github -npm',
        'filetype:js "braintree" "tokenization_key" -github -npm',
        'filetype:js "publishableKey" "stripe" -github -npm',
        'filetype:js.map "sk_live_" -github',
        'filetype:js.map "STRIPE_SECRET" -github',
        'filetype:js.map "api_key" "secret" -github',
        'filetype:js.map "BRAINTREE" "private_key" -github',
        'inurl:"/static/js/" "pk_live_" -github -npm',
        'inurl:"/assets/js/" "pk_live_" -github -npm',
        'inurl:"/build/" filetype:js "pk_live_" -github -npm',
        'inurl:"/dist/" filetype:js "pk_live_" -github -npm',
        'inurl:"/bundle" filetype:js "pk_live_" -github',
        'intext:"sourceMappingURL" "pk_live_" -github',
        
        # ========== REGISTRATION + PAYMENT FLOWS ==========
        'inurl:"/register" intext:"pk_live_" "payment" -github',
        'inurl:"/signup" intext:"stripe" "payment" -github -docs',
        'inurl:"/sign-up" intext:"pk_live_" -github',
        'inurl:"/join" intext:"stripe" "payment" -github -docs',
        'inurl:"/create-account" intext:"pk_live_" -github',
        'inurl:"/onboarding" intext:"stripe" payment -github -docs',
        '"registration" "payment" intext:"pk_live_" -github -docs',
        '"create account" "pay" intext:"pk_live_" -github',
        '"new user" "payment" intext:"stripe" -github -docs',
        'inurl:"/trial" intext:"pk_live_" -github',
        'inurl:"/free-trial" intext:"stripe" "card" -github -docs',
        
        # ========== 2CHECKOUT EXPANDED ==========
        'intext:"2checkout" "publishable_key" -github -docs',
        'intext:"2Checkout.publicKey" -github -docs',
        'intext:"TwoCoInlineCart" -github -docs -2checkout.com',
        'intext:"2checkout" "sid" "mode" "2CO" -github -docs',
        
        # ========== ADDITIONAL INJECTABLE E-COMMERCE URLs ==========
        'inurl:"store_viewProducts.php?cat=" -github',
        'inurl:"shop_detail.php?article=" -github',
        'inurl:"productDetails.php?idProduct=" -github',
        'inurl:"shoppingcart.php?bookid=" -github',
        'inurl:"basket.php?id=" -github',
        'inurl:"viewCart.php?userID=" -github',
        'inurl:"addToCart.php?idProduct=" -github',
        'inurl:"orderFinished.php?cartid=" -github',
        'inurl:"comersus_viewItem.php?idProduct=" -github',
        'inurl:"comersus_listCategoriesAndProducts.php?idCategory=" -github',
        'inurl:"emailToFriend.php?idProduct=" -github',
        'inurl:"catalog_item.php?ID=" -github',
        'inurl:"getbook.php?bookid=" -github',
        'inurl:"productlist.php?fid=" -github',
        'inurl:"product-range.php?rangeID=" -github',
        'inurl:"catalog_main.php?catid=" -github',
        
        # ========== AUTHORIZE.NET (Accept.js) ==========
        'intext:"Accept.dispatchData" -github -docs -authorize.net',
        'intext:"apiLoginID" "clientKey" -github -docs -authorize.net',
        'intext:"js.authorize.net" "Accept.js" -github -docs',
        'intext:"AcceptUI" "apiLoginID" -github -docs',
        'intext:"authorize.net" "login_id" "transaction_key" -github -docs',
        'filetype:env "AUTHORIZE_NET" -github',
        'filetype:env "AUTHORIZENET_LOGIN" OR "AUTHORIZENET_KEY" -github',
        'intext:"x_login" "x_tran_key" -github -docs -authorize.net',
        'inurl:"/checkout" intext:"Accept.js" "apiLoginID" -github',
        '"AUTHORIZE_NET_API_LOGIN_ID" -github -docs',
        '"AUTHORIZE_NET_TRANSACTION_KEY" -github -docs',
        
        # ========== NUVEI / SAFECHARGE ==========
        'intext:"SafeCharge" "merchantId" "merchantSiteId" -github -docs',
        'intext:"safecharge.js" -github -docs -nuvei.com -safecharge.com',
        'intext:"SafeCharge.checkout" -github -docs',
        'intext:"SafeCharge.fields" -github -docs -nuvei.com',
        'intext:"nuvei" "merchantId" "merchantSiteId" -github -docs',
        'filetype:env "NUVEI" OR "SAFECHARGE" -github',
        'intext:"cdn.safecharge.com" -github -docs',
        '"NUVEI_MERCHANT_ID" OR "SAFECHARGE_MERCHANT_ID" -github',
        
        # ========== BLUESNAP ==========
        'intext:"bluesnap" "hostedPaymentFieldsCreate" -github -docs -bluesnap.com',
        'intext:"data-bluesnap" -github -docs -bluesnap.com',
        'intext:"bluesnap.js" "token" -github -docs',
        'intext:"pay.bluesnap.com" -github -docs -bluesnap.com',
        'intext:"sandpay.bluesnap.com" -github -docs',
        'filetype:env "BLUESNAP" -github',
        '"BLUESNAP_API_KEY" OR "BLUESNAP_PASSWORD" -github',
        
        # ========== PAYSAFE ==========
        'intext:"paysafe.checkout.setup" -github -docs -paysafe.com',
        'intext:"hosted.paysafe.com" -github -docs',
        'intext:"paysafe" "apiKey" "environment" "LIVE" -github -docs',
        'intext:"paysafe.checkout" -github -docs -paysafe.com',
        'filetype:env "PAYSAFE" -github',
        '"PAYSAFE_API_KEY" OR "PAYSAFE_API_SECRET" -github',
        
        # ========== OPAYO / SAGE PAY ==========
        'intext:"sagepay" "tokeniseCardDetails" -github -docs',
        'intext:"sagepay.js" "merchantSessionKey" -github -docs',
        'intext:"opayo" "merchantSessionKey" -github -docs',
        'intext:"pi-live.sagepay.com" -github -docs -sagepay.com',
        'filetype:env "SAGEPAY" OR "OPAYO" -github',
        '"SAGEPAY_VENDOR" OR "OPAYO_VENDOR" -github',
        'intext:"sagepay" "vendor" "integration_key" -github -docs',
        
        # ========== PIN PAYMENTS (AUSTRALIA) ==========
        'intext:"Pin.Api" -github -docs -pinpayments.com',
        'intext:"cdn.pinpayments.com" "pin.v2.js" -github -docs',
        'intext:"pinpayments" "publishable" -github -docs',
        'filetype:env "PIN_PAYMENTS" OR "PINPAYMENTS" -github',
        '"PIN_SECRET_KEY" OR "PIN_PUBLISHABLE_KEY" -github',
        
        # ========== BAMBORA / WORLDLINE ==========
        'intext:"customcheckout" "bambora" -github -docs -bambora.com',
        'intext:"customcheckout.bambora" -github -docs',
        'intext:"bambora" "merchant_id" "passcode" -github -docs',
        'filetype:env "BAMBORA" -github',
        '"BAMBORA_MERCHANT_ID" OR "BAMBORA_API_KEY" -github',
        
        # ========== GLOBAL PAYMENTS ==========
        'intext:"GlobalPayments.configure" -github -docs -globalpayments.com',
        'intext:"GlobalPayments.creditCard" -github -docs',
        'intext:"js.globalpay.com" -github -docs -globalpayments.com',
        'intext:"globalpayments" "app_id" "app_key" -github -docs',
        'filetype:env "GLOBAL_PAYMENTS" OR "GLOBALPAY" -github',
        '"GP_APP_ID" OR "GP_APP_KEY" -github',
        
        # ========== SEZZLE ==========
        'intext:"checkout-sdk.sezzle.com" -github -docs -sezzle.com',
        'intext:"sezzle" "publicKey" "apiMode" -github -docs',
        'intext:"Sezzle" "sz-checkout-button" -github -docs -sezzle.com',
        'filetype:env "SEZZLE" -github',
        '"SEZZLE_PUBLIC_KEY" OR "SEZZLE_PRIVATE_KEY" -github',
        
        # ========== GOCARDLESS ==========
        'intext:"GoCardlessDropin.create" -github -docs -gocardless.com',
        'intext:"pay.gocardless.com" "dropin" -github -docs',
        'intext:"gocardless" "access_token" -github -docs -gocardless.com',
        'filetype:env "GOCARDLESS" -github',
        '"GOCARDLESS_ACCESS_TOKEN" OR "GOCARDLESS_ENVIRONMENT" -github',
        
        # ========== DWOLLA ==========
        'intext:"dwolla" "client_id" "client_secret" -github -docs -dwolla.com',
        'intext:"dwolla.js" -github -docs -dwolla.com',
        'intext:"dwolla" "environment" "api_key" -github -docs',
        'filetype:env "DWOLLA" -github',
        '"DWOLLA_KEY" OR "DWOLLA_SECRET" -github',
        
        # ========== PLAID ==========
        'intext:"Plaid.create" "public_key" -github -docs -plaid.com',
        'intext:"plaid" "client_id" "secret" -github -docs -plaid.com',
        'intext:"cdn.plaid.com" "link-initialize" -github -docs',
        'filetype:env "PLAID_SECRET" OR "PLAID_CLIENT_ID" -github',
        '"PLAID_PUBLIC_KEY" -github -docs',
        
        # ========== HELCIM ==========
        'intext:"helcim" "api-token" -github -docs -helcim.com',
        'intext:"helcimjs" -github -docs -helcim.com',
        'filetype:env "HELCIM" -github',
        '"HELCIM_API_TOKEN" -github',
        
        # ========== CLOVER ==========
        'intext:"clover" "access_token" "merchant_id" -github -docs -clover.com',
        'intext:"clover.js" -github -docs -clover.com',
        'intext:"sandbox.dev.clover.com" OR "api.clover.com" "access_token" -github',
        'filetype:env "CLOVER" -github',
        '"CLOVER_API_KEY" OR "CLOVER_MERCHANT_ID" -github',
        
        # ========== PAYTRACE ==========
        'intext:"paytrace" "api_key" -github -docs -paytrace.com',
        'intext:"paytrace" "user_name" "password" -github -docs',
        'filetype:env "PAYTRACE" -github',
        '"PAYTRACE_API_KEY" OR "PAYTRACE_USERNAME" -github',
        
        # ========== USAEPAY ==========
        'intext:"usaepay" "source_key" "pin" -github -docs -usaepay.com',
        'intext:"usaepay" "UmKey" -github -docs',
        'filetype:env "USAEPAY" -github',
        '"USAEPAY_SOURCE_KEY" OR "USAEPAY_PIN" -github',
        
        # ========== iATS PAYMENTS ==========
        'intext:"iats" "agentcode" "password" -github -docs -iatspayments.com',
        'intext:"iatspayments" "agent_code" -github -docs',
        'filetype:env "IATS" -github',
        
        # ========== SHIFT4 ==========
        'intext:"shift4" "api_key" -github -docs -shift4.com',
        'intext:"js.shift4.com" -github -docs',
        'filetype:env "SHIFT4" -github',
        '"SHIFT4_SECRET_KEY" OR "SHIFT4_PUBLIC_KEY" -github',
        
        # ========== RAPYD ==========
        'intext:"rapyd" "access_key" "secret_key" -github -docs -rapyd.net',
        'intext:"sandboxapi.rapyd.net" OR "api.rapyd.net" -github -docs',
        'filetype:env "RAPYD" -github',
        '"RAPYD_ACCESS_KEY" OR "RAPYD_SECRET_KEY" -github',
        
        # ========== DLOCAL ==========
        'intext:"dlocal" "x_login" "x_trans_key" -github -docs -dlocal.com',
        'intext:"dlocal" "api_key" "secret_key" -github -docs',
        'filetype:env "DLOCAL" -github',
        '"DLOCAL_API_KEY" OR "DLOCAL_SECRET_KEY" -github',
        
        # ========== EBANX ==========
        'intext:"ebanx" "integration_key" -github -docs -ebanx.com',
        'intext:"ebanx" "public_integration_key" -github -docs',
        'filetype:env "EBANX" -github',
        '"EBANX_INTEGRATION_KEY" -github',
        
        # ========== CCAVENUE ==========
        'intext:"ccavenue" "merchant_id" "access_code" "working_key" -github -docs',
        'intext:"ccavenue" "merchant_id" -github -docs -ccavenue.com',
        'filetype:env "CCAVENUE" -github',
        '"CCAVENUE_MERCHANT_ID" OR "CCAVENUE_WORKING_KEY" -github',
        
        # ========== PAYMOB (EGYPT/MENA) ==========
        'intext:"paymob" "api_key" "integration_id" -github -docs -paymob.com',
        'intext:"accept.paymob.com" -github -docs',
        'filetype:env "PAYMOB" -github',
        '"PAYMOB_API_KEY" OR "PAYMOB_INTEGRATION_ID" -github',
        
        # ========== AIRWALLEX ==========
        'intext:"airwallex" "client_id" "api_key" -github -docs -airwallex.com',
        'intext:"checkout.airwallex.com" -github -docs',
        'filetype:env "AIRWALLEX" -github',
        '"AIRWALLEX_API_KEY" OR "AIRWALLEX_CLIENT_ID" -github',
        
        # ========== PAYONEER ==========
        'intext:"payoneer" "client_id" "client_secret" -github -docs -payoneer.com',
        'filetype:env "PAYONEER" -github',
        '"PAYONEER_API_KEY" -github',
        
        # ========== SKRILL ==========
        'intext:"skrill" "merchant_id" "secret_word" -github -docs -skrill.com',
        'intext:"pay.skrill.com" "pay_to_email" -github -docs',
        'filetype:env "SKRILL" -github',
        '"SKRILL_MERCHANT_ID" OR "SKRILL_SECRET" -github',
        
        # ========== GCASH / MAYA (PHILIPPINES) ==========
        'intext:"gcash" "api_key" "merchant" -github -docs',
        'intext:"maya" "public_key" "secret_key" checkout -github -docs',
        'intext:"paymaya" "pk-" -github -docs -paymaya.com',
        
        # ========== LIGHTSPEED ==========
        'intext:"lightspeed" "api_key" "api_secret" -github -docs -lightspeedhq.com',
        'filetype:env "LIGHTSPEED" -github',
        '"LIGHTSPEED_API_KEY" -github',
        
        # ========== TOAST (RESTAURANT POS) ==========
        'intext:"toast" "client_id" "client_secret" "restaurant" -github -docs -toasttab.com',
        'filetype:env "TOAST_CLIENT" -github',
        
        # ========== ADDITIONAL PAYMENT .ENV LEAKS ==========
        'filetype:env "PAYMENT_SECRET" OR "PAYMENT_API_KEY" -github',
        'filetype:env "MERCHANT_SECRET" OR "MERCHANT_KEY" -github',
        'filetype:env "GATEWAY_KEY" OR "GATEWAY_SECRET" -github',
        'filetype:env "CHECKOUT_SECRET" OR "CHECKOUT_KEY" -github',
        'filetype:env "TRANSACTION_KEY" -github',
        'filetype:env "CARD_PROCESSING" -github',
        
        # ========== ADDITIONAL JS BUNDLE LEAKS ==========
        'inurl:".js" "apiLoginID" "clientKey" -github',
        'inurl:".js" "SafeCharge" "merchantId" -github',
        'inurl:".js" "bluesnap" "token" -github',
        'inurl:".js" "paysafe" "apiKey" -github',
        'inurl:".js" "sagepay" "merchantSessionKey" -github',
        'inurl:".js" "GlobalPayments.configure" -github',
        'inurl:".js" "Pin.Api" -github',
        'inurl:".js" "customcheckout" "bambora" -github',
        'inurl:".js.map" "authorize" "login" "transaction_key" -github',
        'inurl:".js.map" "nuvei" OR "safecharge" "merchant" -github',
        
        # ========== CONFIG FILE LEAKS (MULTI-PROCESSOR) ==========
        'filetype:json "api_key" "merchant_id" "payment" -github -npm',
        'filetype:yaml "payment_gateway" "api_key" "secret" -github',
        'filetype:xml "merchantID" "transactionKey" -github',
        'filetype:properties "payment" "api.key" "secret" -github',
        'filetype:conf "merchant" "password" "payment" -github',
        'filetype:ini "payment" "secret_key" "api_key" -github',
        'filetype:toml "payment" "api_key" -github',
        
        # ========== CHECKOUT PAGE DISCOVERY (GENERIC INJECTABLE) ==========
        'inurl:"payment.php?order_id=" -github',
        'inurl:"checkout.php?session=" -github',
        'inurl:"pay.php?invoice=" -github',
        'inurl:"process_payment.php?id=" -github',
        'inurl:"complete_order.php?ref=" -github',
        'inurl:"billing.php?account=" -github',
        'inurl:"subscribe.php?plan=" -github',
        'inurl:"donate.php?amount=" -github',
        'inurl:"purchase.php?item=" -github',
        'inurl:"transaction.php?txn=" -github',
    ]

    def __init__(self, params_dir: str = None, custom_dork_file: str = None):
        """Initialize the dork generator.
        
        Args:
            params_dir: Directory containing keyword parameter files.
                        Defaults to ./params/ relative to this file.
            custom_dork_file: Path to external custom dorks file (one dork per line).
                              Defaults to params/custom_dorks.txt if it exists.
        """
        if params_dir is None:
            params_dir = os.path.join(os.path.dirname(__file__), "params")
        
        self.params_dir = Path(params_dir)
        self.params: Dict[str, List[str]] = {}
        self.patterns = self.DEFAULT_PATTERNS.copy()
        self.custom_dorks: List[str] = []
        
        # Load parameter files
        self._load_params()
        
        # Load custom dorks from external file
        if custom_dork_file is None:
            custom_dork_file = str(self.params_dir / "custom_dorks.txt")
        self._load_custom_dorks(custom_dork_file)
        
        logger.info(f"DorkGenerator initialized: {len(self.patterns)} patterns, "
                    f"{sum(len(v) for v in self.params.values())} total keywords, "
                    f"{len(self.custom_dorks)} custom dorks")

    def _load_custom_dorks(self, filepath: str):
        """Load pre-built dorks from an external file (one dork per line)."""
        path = Path(filepath)
        if not path.exists():
            logger.info(f"No custom dork file found at {filepath} — skipping")
            return
        
        count = 0
        with open(path, "r", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    self.custom_dorks.append(line)
                    count += 1
        
        logger.info(f"Loaded {count:,} custom dorks from {path.name}")

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

    def generate_all(self, max_total: int = 250000, max_per_pattern: int = 500) -> List[str]:
        """Generate all dorks from all patterns + static dorks.
        
        Args:
            max_total: Maximum total dorks to generate
            max_per_pattern: Maximum dorks per pattern
            
        Returns:
            Deduplicated list of dork queries
        """
        all_dorks: Set[str] = set()
        
        # 1. Add static dorks first (highest priority — operator-rich, SK-focused)
        for dork in self.STATIC_DORKS:
            all_dorks.add(dork)
        
        static_count = len(all_dorks)
        logger.info(f"Added {static_count} static dorks")
        
        # 2. Add custom dorks (high priority — user-supplied, converted to operators)
        custom_added = 0
        for dork in self.custom_dorks:
            if len(all_dorks) >= max_total:
                break
            all_dorks.add(dork)
            custom_added += 1
        
        custom_count = len(all_dorks) - static_count
        logger.info(f"Added {custom_count:,} custom dorks (from {len(self.custom_dorks):,} loaded)")
        
        # 3. Generate from patterns (fill remaining capacity)
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
        
        dynamic_count = len(result) - static_count - custom_count
        logger.info(f"Generated {len(result):,} total unique dorks "
                    f"({static_count} static + {custom_count:,} custom + {dynamic_count:,} dynamic)")
        
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
