#!/usr/bin/env python3
"""
Generate 200,000+ payment-focused Google dorks for MadyDorker Bot 2.
Heavy emphasis on: payment gateways, checkout pages, card processing,
Stripe/Braintree/PayPal/Square/Adyen keys, merchant configs, PCI data.
"""
import random

with open("/home/null/Documents/knfornewdork.txt", "r") as f:
    keywords = [line.strip() for line in f if line.strip()]

print(f"Loaded {len(keywords)} keywords")

TARGET = 200000

# ══════════════════════════════════════════════════════════════════════
# MEGA TEMPLATE SET — Payment-focused dorking
# ══════════════════════════════════════════════════════════════════════

# ─── STRIPE (the big one) ─────────────────────────────────────────
stripe_templates = [
    'intext:"pk_live_" "{KW}"',
    'intext:"sk_live_" "{KW}"',
    'intext:"pk_test_" "{KW}"',
    'intext:"sk_test_" "{KW}"',
    'intext:"stripe_publishable_key" "{KW}"',
    'intext:"stripe_secret_key" "{KW}"',
    'intext:"STRIPE_PUBLISHABLE_KEY" "{KW}"',
    'intext:"STRIPE_SECRET_KEY" "{KW}"',
    'intext:"STRIPE_KEY" "{KW}"',
    'intext:"STRIPE_API_KEY" "{KW}"',
    'intext:"stripe.createToken" "{KW}"',
    'intext:"stripe.confirmCardPayment" "{KW}"',
    'intext:"stripe.paymentIntents" "{KW}"',
    'intext:"stripe.charges.create" "{KW}"',
    'intext:"stripe.customers.create" "{KW}"',
    'intext:"Stripe.js" "{KW}"',
    'intext:"stripe-button" "{KW}"',
    'intext:"checkout.stripe.com" "{KW}"',
    'intext:"js.stripe.com" "{KW}"',
    'intext:"stripe.com/v1" "{KW}"',
    'intext:"paymentIntent" "{KW}"',
    'intext:"payment_method" "{KW}"',
    'intext:"stripe.elements" "{KW}"',
    'intext:"stripe.redirectToCheckout" "{KW}"',
    'intext:"stripe.handleCardPayment" "{KW}"',
    'intext:"stripe_webhook_secret" "{KW}"',
    'intext:"whsec_" "{KW}"',
    'intext:"price_" "stripe" "{KW}"',
    'intext:"prod_" "stripe" "{KW}"',
    'intext:"cus_" "stripe" "{KW}"',
    'intext:"pi_" "stripe" "{KW}"',
    'intext:"sub_" "stripe" "{KW}"',
    'intext:"acct_" "stripe" "{KW}"',
    'filetype:js "pk_live_" "{KW}"',
    'filetype:js "sk_live_" "{KW}"',
    'filetype:js "stripe" "key" "{KW}"',
    'filetype:env "STRIPE" "{KW}"',
    'filetype:env "pk_live_" "{KW}"',
    'filetype:env "sk_live_" "{KW}"',
    'filetype:json "stripe" "secret" "{KW}"',
    'filetype:json "pk_live_" "{KW}"',
    'filetype:yaml "stripe" "key" "{KW}"',
    'filetype:yml "stripe_api" "{KW}"',
    'filetype:php "stripe" "secret_key" "{KW}"',
    'filetype:py "stripe.api_key" "{KW}"',
    'filetype:rb "Stripe.api_key" "{KW}"',
    'inurl:stripe "{KW}"',
    'inurl:stripe-webhook "{KW}"',
    'inurl:stripe/checkout "{KW}"',
    'inurl:stripe/payment "{KW}"',
]

# ─── PAYPAL ───────────────────────────────────────────────────────
paypal_templates = [
    'intext:"paypal.Buttons" "{KW}"',
    'intext:"paypal.BUTTONS" "{KW}"',
    'intext:"paypal-button" "{KW}"',
    'intext:"PAYPAL_CLIENT_ID" "{KW}"',
    'intext:"PAYPAL_SECRET" "{KW}"',
    'intext:"PAYPAL_CLIENT_SECRET" "{KW}"',
    'intext:"paypal_client_id" "{KW}"',
    'intext:"paypal_secret" "{KW}"',
    'intext:"paypal.me" "{KW}"',
    'intext:"paypal-checkout" "{KW}"',
    'intext:"paypalobjects.com" "{KW}"',
    'intext:"paypal.com/sdk" "{KW}"',
    'intext:"paypalrestapi" "{KW}"',
    'intext:"payflowpro" "{KW}"',
    'filetype:env "PAYPAL" "{KW}"',
    'filetype:js "paypal" "client" "{KW}"',
    'filetype:json "paypal" "secret" "{KW}"',
    'inurl:paypal "{KW}" inurl:checkout',
    'inurl:paypal-return "{KW}"',
    'inurl:paypal-callback "{KW}"',
]

# ─── BRAINTREE ────────────────────────────────────────────────────
braintree_templates = [
    'intext:"braintree" "{KW}" inurl:payment',
    'intext:"braintree.dropin" "{KW}"',
    'intext:"braintree.client" "{KW}"',
    'intext:"BRAINTREE_MERCHANT_ID" "{KW}"',
    'intext:"BRAINTREE_PUBLIC_KEY" "{KW}"',
    'intext:"BRAINTREE_PRIVATE_KEY" "{KW}"',
    'intext:"braintree_merchant_id" "{KW}"',
    'intext:"braintreegateway" "{KW}"',
    'intext:"braintree-web" "{KW}"',
    'intext:"client_token" "braintree" "{KW}"',
    'filetype:env "BRAINTREE" "{KW}"',
    'filetype:js "braintree" "{KW}"',
    'filetype:json "braintree" "merchant" "{KW}"',
    'filetype:php "Braintree_Configuration" "{KW}"',
]

# ─── SQUARE ───────────────────────────────────────────────────────
square_templates = [
    'intext:"square.payment" "{KW}"',
    'intext:"SQUARE_ACCESS_TOKEN" "{KW}"',
    'intext:"SQUARE_APPLICATION_ID" "{KW}"',
    'intext:"square_access_token" "{KW}"',
    'intext:"squareup.com" "{KW}"',
    'intext:"square-payment-form" "{KW}"',
    'intext:"sq0atp-" "{KW}"',
    'intext:"sq0csp-" "{KW}"',
    'intext:"sq0idp-" "{KW}"',
    'filetype:env "SQUARE" "{KW}"',
    'filetype:js "square" "applicationId" "{KW}"',
    'filetype:json "square" "access_token" "{KW}"',
]

# ─── ADYEN ────────────────────────────────────────────────────────
adyen_templates = [
    'intext:"adyen" "{KW}" inurl:pay',
    'intext:"adyen-checkout" "{KW}"',
    'intext:"ADYEN_API_KEY" "{KW}"',
    'intext:"ADYEN_MERCHANT" "{KW}"',
    'intext:"adyen.encrypt" "{KW}"',
    'intext:"adyen_client_key" "{KW}"',
    'intext:"checkoutshopper" "adyen" "{KW}"',
    'filetype:env "ADYEN" "{KW}"',
    'filetype:js "adyen" "clientKey" "{KW}"',
    'filetype:json "adyen" "apiKey" "{KW}"',
]

# ─── AUTHORIZE.NET ────────────────────────────────────────────────
authnet_templates = [
    'intext:"authorize.net" "{KW}"',
    'intext:"AUTHORIZE_LOGIN_ID" "{KW}"',
    'intext:"AUTHORIZE_TRANSACTION_KEY" "{KW}"',
    'intext:"authorizenet" "{KW}"',
    'intext:"x_login" "x_tran_key" "{KW}"',
    'intext:"Accept.js" "authorize" "{KW}"',
    'filetype:env "AUTHORIZE" "{KW}"',
    'filetype:php "AuthorizeNet" "{KW}"',
]

# ─── OTHER GATEWAYS (massive) ────────────────────────────────────
other_gateway_templates = [
    'intext:"merchant_id" "{KW}"',
    'intext:"merchant_key" "{KW}"',
    'intext:"gateway_token" "{KW}"',
    'intext:"gateway_secret" "{KW}"',
    'intext:"payment_gateway" "{KW}"',
    'intext:"RAZORPAY_KEY" "{KW}"',
    'intext:"rzp_live_" "{KW}"',
    'intext:"rzp_test_" "{KW}"',
    'intext:"RAZORPAY_SECRET" "{KW}"',
    'intext:"razorpay_key_id" "{KW}"',
    'intext:"razorpay_key_secret" "{KW}"',
    'intext:"MOLLIE_API_KEY" "{KW}"',
    'intext:"live_" "mollie" "{KW}"',
    'intext:"test_" "mollie" "{KW}"',
    'intext:"KLARNA" "api" "{KW}"',
    'intext:"klarna.com" "{KW}"',
    'intext:"afterpay" "{KW}" "token"',
    'intext:"2checkout" "{KW}"',
    'intext:"TWOCHECKOUT" "{KW}"',
    'intext:"worldpay" "{KW}"',
    'intext:"WORLDPAY_MERCHANT" "{KW}"',
    'intext:"WORLDPAY_INSTALLATION_ID" "{KW}"',
    'intext:"cybersource" "{KW}"',
    'intext:"CYBERSOURCE_MERCHANT" "{KW}"',
    'intext:"CYBERSOURCE_API_KEY" "{KW}"',
    'intext:"moneris" "{KW}"',
    'intext:"MONERIS_STORE_ID" "{KW}"',
    'intext:"MONERIS_API_TOKEN" "{KW}"',
    'intext:"payu" "{KW}" "key"',
    'intext:"PAYU_MERCHANT" "{KW}"',
    'intext:"PAYU_SALT" "{KW}"',
    'intext:"eway" "{KW}" "api_key"',
    'intext:"EWAY_API_KEY" "{KW}"',
    'intext:"EWAY_PASSWORD" "{KW}"',
    'intext:"recurly" "{KW}" "key"',
    'intext:"RECURLY_API_KEY" "{KW}"',
    'intext:"RECURLY_PUBLIC_KEY" "{KW}"',
    'intext:"chargebee" "{KW}"',
    'intext:"CHARGEBEE_API_KEY" "{KW}"',
    'intext:"CHARGEBEE_SITE" "{KW}"',
    'intext:"gocardless" "{KW}"',
    'intext:"GOCARDLESS_ACCESS_TOKEN" "{KW}"',
    'intext:"paddle" "{KW}" "vendor"',
    'intext:"PADDLE_VENDOR_ID" "{KW}"',
    'intext:"PADDLE_API_KEY" "{KW}"',
    'intext:"bluesnap" "{KW}"',
    'intext:"BLUESNAP_API_KEY" "{KW}"',
    'intext:"paysafe" "{KW}"',
    'intext:"PAYSAFE_API_KEY" "{KW}"',
    'intext:"firstdata" "{KW}"',
    'intext:"FIRST_DATA_GATEWAY" "{KW}"',
    'intext:"wepay" "{KW}"',
    'intext:"WEPAY_CLIENT_ID" "{KW}"',
    'intext:"dwolla" "{KW}" "key"',
    'intext:"DWOLLA_KEY" "{KW}"',
    'intext:"flutterwave" "{KW}"',
    'intext:"FLUTTERWAVE_SECRET" "{KW}"',
    'intext:"FLUTTERWAVE_PUBLIC_KEY" "{KW}"',
    'intext:"paystack" "{KW}"',
    'intext:"PAYSTACK_SECRET" "{KW}"',
    'intext:"PAYSTACK_PUBLIC_KEY" "{KW}"',
    'intext:"sk_live" "paystack" "{KW}"',
    'intext:"pk_live" "paystack" "{KW}"',
    'intext:"opayo" "{KW}"',
    'intext:"sagepay" "{KW}"',
    'intext:"SAGEPAY_VENDOR" "{KW}"',
    'intext:"checkout.com" "{KW}" "secret"',
    'intext:"CHECKOUT_SECRET_KEY" "{KW}"',
    'intext:"CHECKOUT_PUBLIC_KEY" "{KW}"',
    'intext:"paynow" "{KW}"',
    'intext:"peach" "{KW}" "payment"',
    'intext:"PEACH_API_KEY" "{KW}"',
    'intext:"nmi" "{KW}" "gateway"',
    'intext:"NMI_SECURITY_KEY" "{KW}"',
    'intext:"usaepay" "{KW}"',
    'intext:"USAEPAY_KEY" "{KW}"',
    'intext:"nuvei" "{KW}"',
    'intext:"NUVEI_SECRET" "{KW}"',
    'intext:"global payments" "{KW}"',
    'intext:"heartland" "{KW}" "key"',
    'intext:"vindicia" "{KW}"',
    'intext:"bambora" "{KW}"',
    'intext:"BAMBORA_MERCHANT_ID" "{KW}"',
    'intext:"payeezy" "{KW}"',
    'intext:"PAYEEZY_API_KEY" "{KW}"',
    'intext:"iyzico" "{KW}"',
    'intext:"IYZICO_API_KEY" "{KW}"',
    'intext:"mercadopago" "{KW}"',
    'intext:"MERCADOPAGO_ACCESS_TOKEN" "{KW}"',
    'intext:"mpago" "{KW}" "token"',
    'intext:"pagseguro" "{KW}"',
    'intext:"PAGSEGURO_TOKEN" "{KW}"',
    'intext:"midtrans" "{KW}"',
    'intext:"MIDTRANS_SERVER_KEY" "{KW}"',
    'intext:"xendit" "{KW}"',
    'intext:"XENDIT_SECRET_KEY" "{KW}"',
    'intext:"instamojo" "{KW}"',
    'intext:"INSTAMOJO_API_KEY" "{KW}"',
    'intext:"rapyd" "{KW}"',
    'intext:"RAPYD_SECRET_KEY" "{KW}"',
    'filetype:env "MERCHANT" "{KW}"',
    'filetype:env "GATEWAY" "{KW}"',
    'filetype:env "RAZORPAY" "{KW}"',
    'filetype:env "MOLLIE" "{KW}"',
    'filetype:env "PAYSTACK" "{KW}"',
    'filetype:env "FLUTTERWAVE" "{KW}"',
    'filetype:env "CHECKOUT_COM" "{KW}"',
    'filetype:env "MERCADOPAGO" "{KW}"',
]

# ─── CHECKOUT / PAYMENT PAGES ────────────────────────────────────
checkout_templates = [
    'inurl:checkout "{KW}"',
    'inurl:payment "{KW}"',
    'inurl:billing "{KW}"',
    'inurl:cart "{KW}"',
    'inurl:order "{KW}"',
    'inurl:pay "{KW}"',
    'inurl:purchase "{KW}"',
    'inurl:subscribe "{KW}"',
    'inurl:donate "{KW}"',
    'inurl:invoice "{KW}"',
    'inurl:receipt "{KW}"',
    'inurl:transaction "{KW}"',
    'inurl:charge "{KW}"',
    'inurl:pricing "{KW}"',
    'inurl:membership "{KW}"',
    'inurl:upgrade "{KW}"',
    'inurl:renew "{KW}"',
    'inurl:process-payment "{KW}"',
    'inurl:complete-order "{KW}"',
    'inurl:confirm-payment "{KW}"',
    'inurl:payment-form "{KW}"',
    'inurl:card-details "{KW}"',
    'inurl:secure-checkout "{KW}"',
    'inurl:payment-info "{KW}"',
    'inurl:billing-info "{KW}"',
    'inurl:payment-method "{KW}"',
    'inurl:add-card "{KW}"',
    'inurl:update-card "{KW}"',
    'inurl:saved-cards "{KW}"',
    'inurl:payment-success "{KW}"',
    'inurl:payment-failed "{KW}"',
    'inurl:pay-now "{KW}"',
    'inurl:thankyou "{KW}" "order"',
    'inurl:confirmation "{KW}" "payment"',
    'inurl:checkout/step "{KW}"',
    'inurl:checkout/shipping "{KW}"',
    'inurl:checkout/review "{KW}"',
    'inurl:checkout/payment "{KW}"',
    'inurl:one-page-checkout "{KW}"',
    'inurl:express-checkout "{KW}"',
    'inurl:guest-checkout "{KW}"',
    'intitle:"checkout" "{KW}"',
    'intitle:"payment" "{KW}"',
    'intitle:"billing" "{KW}"',
    'intitle:"secure checkout" "{KW}"',
    'intitle:"complete your order" "{KW}"',
    'intitle:"enter payment" "{KW}"',
    'intitle:"card details" "{KW}"',
    '"enter your card" "{KW}"',
    '"card number" "expiry" "{KW}"',
    '"credit card number" "{KW}"',
    '"billing address" "card" "{KW}"',
    '"secure payment" "{KW}"',
    '"payment information" "{KW}"',
    '"order summary" "pay" "{KW}"',
    '"complete purchase" "{KW}"',
    '"place order" "{KW}"',
    '"submit payment" "{KW}"',
    '"proceed to payment" "{KW}"',
    '"pay with card" "{KW}"',
]

# ─── E-COMMERCE PLATFORMS ─────────────────────────────────────────
ecom_templates = [
    'site:myshopify.com "{KW}"',
    'site:myshopify.com "{KW}" "checkout"',
    'site:myshopify.com "{KW}" "payment"',
    'inurl:myshopify.com "{KW}"',
    '"powered by Shopify" "{KW}"',
    '"Shopify.checkout" "{KW}"',
    '"shopify-payment" "{KW}"',
    'inurl:shopify "{KW}" "checkout"',
    'inurl:shopify "{KW}" "cart"',
    'inurl:"/cart/" "{KW}" "shopify"',
    'inurl:"/collections/" "{KW}" site:myshopify.com',
    '"powered by WooCommerce" "{KW}"',
    'inurl:woocommerce "{KW}"',
    'inurl:wc-api "{KW}"',
    'inurl:"?wc-api=" "{KW}"',
    '"woocommerce_checkout" "{KW}"',
    '"WC_Gateway" "{KW}"',
    '"woocommerce-gateway-stripe" "{KW}"',
    '"woocommerce-gateway-paypal" "{KW}"',
    '"Add to Cart" "{KW}" inurl:product',
    '"Buy Now" "{KW}" inurl:shop',
    '"powered by Magento" "{KW}"',
    'inurl:magento "{KW}" "checkout"',
    'inurl:magento "{KW}" "onepage"',
    '"powered by PrestaShop" "{KW}"',
    'inurl:prestashop "{KW}"',
    '"powered by OpenCart" "{KW}"',
    'inurl:opencart "{KW}"',
    '"powered by BigCommerce" "{KW}"',
    'inurl:bigcommerce "{KW}"',
    '"powered by Squarespace" "{KW}"',
    '"powered by Wix" "{KW}" "payment"',
    'inurl:etsy.com "{KW}"',
    'inurl:gumroad.com "{KW}"',
    'inurl:sellfy.com "{KW}"',
    'inurl:paddle.com "{KW}"',
    'inurl:lemonsqueezy "{KW}"',
    'inurl:product "{KW}" "price"',
    'inurl:shop "{KW}" "checkout"',
    'inurl:store "{KW}" "payment"',
    'inurl:products "{KW}" "add to cart"',
]

# ─── CONFIG LEAKS / ENV FILES ────────────────────────────────────
config_templates = [
    'filetype:env "{KW}"',
    'filetype:env "SECRET_KEY" "{KW}"',
    'filetype:env "API_KEY" "{KW}"',
    'filetype:env "DATABASE_URL" "{KW}"',
    'filetype:env "PRIVATE_KEY" "{KW}"',
    'filetype:env "ACCESS_TOKEN" "{KW}"',
    'filetype:env "CLIENT_SECRET" "{KW}"',
    'filetype:env "DB_PASSWORD" "{KW}"',
    'filetype:env "AWS_SECRET" "{KW}"',
    'filetype:env "SENDGRID" "{KW}"',
    'filetype:env "TWILIO" "{KW}"',
    'filetype:env "FIREBASE" "{KW}"',
    'filetype:json "api_key" "{KW}"',
    'filetype:json "secret_key" "{KW}"',
    'filetype:json "client_secret" "{KW}"',
    'filetype:yaml "api_key" "{KW}"',
    'filetype:yml "secret" "{KW}"',
    'filetype:yml "password" "{KW}"',
    'filetype:conf "password" "{KW}"',
    'filetype:cfg "key" "{KW}"',
    'filetype:ini "token" "{KW}"',
    'filetype:toml "secret" "{KW}"',
    'filetype:xml "password" "{KW}"',
    'filetype:xml "apiKey" "{KW}"',
    'filetype:properties "password" "{KW}"',
    'filetype:properties "secret" "{KW}"',
    'filetype:php "db_password" "{KW}"',
    'filetype:php "api_key" "{KW}"',
    'filetype:py "SECRET_KEY" "{KW}"',
    'filetype:rb "secret_key" "{KW}"',
    'inurl:.env "{KW}"',
    'inurl:.env.local "{KW}"',
    'inurl:.env.production "{KW}"',
    'inurl:.env.backup "{KW}"',
    'inurl:config.json "{KW}"',
    'inurl:settings.json "{KW}"',
    'inurl:secrets.json "{KW}"',
    'inurl:wp-config.php "{KW}"',
    'inurl:configuration.php "{KW}"',
    'inurl:database.yml "{KW}"',
    'inurl:credentials "{KW}"',
    'inurl:application.properties "{KW}"',
    'inurl:appsettings.json "{KW}"',
    'inurl:web.config "{KW}"',
    'inurl:.htpasswd "{KW}"',
]

# ─── CARD DATA / PCI EXPOSURE ────────────────────────────────────
card_data_templates = [
    '"card_number" "{KW}"',
    '"card_holder" "{KW}"',
    '"card_expiry" "{KW}"',
    '"card_cvv" "{KW}"',
    '"cc_number" "{KW}"',
    '"ccnum" "{KW}"',
    '"cardnumber" "{KW}"',
    '"cardholder" "{KW}"',
    '"card_exp_month" "{KW}"',
    '"card_exp_year" "{KW}"',
    '"expiration_date" "card" "{KW}"',
    '"security_code" "card" "{KW}"',
    'filetype:sql "card_number" "{KW}"',
    'filetype:sql "credit_card" "{KW}"',
    'filetype:sql "cc_num" "{KW}"',
    'filetype:csv "card" "expiry" "{KW}"',
    'filetype:csv "visa" "{KW}"',
    'filetype:csv "mastercard" "{KW}"',
    'filetype:log "card_number" "{KW}"',
    'filetype:log "credit_card" "{KW}"',
    'filetype:log "payment" "card" "{KW}"',
    'filetype:txt "4111" "{KW}"',
    'filetype:txt "card" "cvv" "{KW}"',
    'intext:"card_token" "{KW}"',
    'intext:"payment_token" "{KW}"',
    'intext:"pan" "expiry" "cvv" "{KW}"',
    '"billing_cc_number" "{KW}"',
    '"payment_card_number" "{KW}"',
]

# ─── DATABASE / SQL DUMPS ────────────────────────────────────────
database_templates = [
    'filetype:sql "{KW}"',
    'filetype:sql "INSERT INTO" "{KW}"',
    'filetype:sql "CREATE TABLE" "{KW}"',
    'filetype:sql "payment" "{KW}"',
    'filetype:sql "orders" "{KW}"',
    'filetype:sql "customers" "{KW}"',
    'filetype:sql "transactions" "{KW}"',
    'filetype:sql "users" "password" "{KW}"',
    'filetype:csv "{KW}" "email"',
    'filetype:csv "{KW}" "phone"',
    'filetype:csv "{KW}" "amount"',
    'filetype:csv "{KW}" "transaction"',
    'filetype:xls "{KW}"',
    'filetype:xlsx "{KW}" "payment"',
    'filetype:bak "{KW}"',
    'filetype:dump "{KW}"',
    'filetype:log "{KW}" "transaction"',
    'filetype:log "{KW}" "error"',
    'filetype:log "payment" "{KW}"',
    'filetype:log "charge" "{KW}"',
    'filetype:log "refund" "{KW}"',
    'inurl:phpmyadmin "{KW}"',
    'inurl:adminer "{KW}"',
    'intitle:"index of" "{KW}" "sql"',
    'intitle:"index of" "{KW}" "backup"',
    'intitle:"index of" "{KW}" "dump"',
    'intitle:"index of" "{KW}" "database"',
    'intitle:"index of" "{KW}" ".csv"',
    'intitle:"index of" "{KW}" ".bak"',
]

# ─── ADMIN PANELS ────────────────────────────────────────────────
admin_templates = [
    'inurl:admin "{KW}"',
    'inurl:admin/payment "{KW}"',
    'inurl:admin/orders "{KW}"',
    'inurl:admin/transactions "{KW}"',
    'inurl:admin/billing "{KW}"',
    'inurl:admin/gateway "{KW}"',
    'inurl:admin/settings/payment "{KW}"',
    'inurl:dashboard "{KW}"',
    'inurl:dashboard/payment "{KW}"',
    'inurl:panel "{KW}"',
    'inurl:cpanel "{KW}"',
    'inurl:wp-admin "{KW}"',
    'inurl:administrator "{KW}"',
    'inurl:manage "{KW}"',
    'inurl:backend "{KW}"',
    'inurl:portal "{KW}"',
    'inurl:console "{KW}"',
    'intitle:"admin panel" "{KW}"',
    'intitle:"dashboard" "{KW}" inurl:admin',
    'intitle:"login" "{KW}" inurl:admin',
    'intitle:"control panel" "{KW}"',
    'intitle:"merchant dashboard" "{KW}"',
    'intitle:"payment settings" "{KW}"',
]

# ─── API ENDPOINTS ───────────────────────────────────────────────
api_templates = [
    'inurl:api "{KW}"',
    'inurl:api/v1 "{KW}"',
    'inurl:api/v2 "{KW}"',
    'inurl:api/v3 "{KW}"',
    'inurl:api/payment "{KW}"',
    'inurl:api/checkout "{KW}"',
    'inurl:api/charge "{KW}"',
    'inurl:api/charges "{KW}"',
    'inurl:api/token "{KW}"',
    'inurl:api/transactions "{KW}"',
    'inurl:api/orders "{KW}"',
    'inurl:api/refund "{KW}"',
    'inurl:api/subscription "{KW}"',
    'inurl:api/invoice "{KW}"',
    'inurl:api/customer "{KW}"',
    'inurl:graphql "{KW}"',
    'inurl:rest "{KW}"',
    'inurl:webhook "{KW}"',
    'inurl:webhook/payment "{KW}"',
    'inurl:webhook/stripe "{KW}"',
    'inurl:callback "{KW}"',
    'inurl:callback/payment "{KW}"',
    'inurl:endpoint "{KW}"',
    'inurl:swagger "{KW}"',
    'inurl:api-docs "{KW}"',
    'inurl:swagger-ui "{KW}" "payment"',
    'inurl:postman "{KW}" "payment"',
    '"X-API-Key" "{KW}"',
    '"Authorization: Bearer" "{KW}"',
    '"api_key" "payment" "{KW}"',
]

# ─── SQLI TARGET PARAMETERS ─────────────────────────────────────
sqli_templates = [
    'inurl:id= "{KW}"',
    'inurl:item= "{KW}"',
    'inurl:product_id= "{KW}"',
    'inurl:order_id= "{KW}"',
    'inurl:cat= "{KW}"',
    'inurl:page= "{KW}"',
    'inurl:view= "{KW}"',
    'inurl:search= "{KW}"',
    'inurl:query= "{KW}"',
    'inurl:category= "{KW}"',
    'inurl:user= "{KW}"',
    'inurl:action= "{KW}"',
    'inurl:type= "{KW}"',
    'inurl:sort= "{KW}"',
    'inurl:filter= "{KW}"',
    'inurl:ref= "{KW}"',
    'inurl:redirect= "{KW}"',
    'inurl:file= "{KW}"',
    'inurl:download= "{KW}"',
    'inurl:invoice_id= "{KW}"',
    'inurl:payment_id= "{KW}"',
    'inurl:transaction_id= "{KW}"',
    'inurl:receipt_id= "{KW}"',
    'inurl:customer_id= "{KW}"',
]

# ─── CLOUD STORAGE LEAKS ─────────────────────────────────────────
cloud_templates = [
    'site:s3.amazonaws.com "{KW}"',
    'site:s3.amazonaws.com "{KW}" "payment"',
    'site:s3.amazonaws.com "{KW}" "card"',
    'site:blob.core.windows.net "{KW}"',
    'site:storage.googleapis.com "{KW}"',
    'site:firebaseio.com "{KW}"',
    'site:digitaloceanspaces.com "{KW}"',
    'inurl:s3.amazonaws "{KW}"',
    'inurl:s3.amazonaws "{KW}" "backup"',
    'inurl:firebase "{KW}" "payment"',
    'inurl:firebase "{KW}" "users"',
    'inurl:storage.cloud "{KW}"',
    'inurl:herokuapp.com "{KW}" "payment"',
    'inurl:vercel.app "{KW}" "checkout"',
    'inurl:netlify.app "{KW}" "payment"',
]

# ─── EXPOSED DIRECTORIES ─────────────────────────────────────────
directory_templates = [
    'intitle:"index of" "{KW}"',
    'intitle:"index of" /backup "{KW}"',
    'intitle:"index of" /config "{KW}"',
    'intitle:"index of" /data "{KW}"',
    'intitle:"index of" /uploads "{KW}"',
    'intitle:"index of" /private "{KW}"',
    'intitle:"index of" /secret "{KW}"',
    'intitle:"index of" /logs "{KW}"',
    'intitle:"index of" /payments "{KW}"',
    'intitle:"index of" /exports "{KW}"',
    'intitle:"index of" /reports "{KW}"',
    'intitle:"index of" /invoices "{KW}"',
    'filetype:pdf "{KW}" "invoice"',
    'filetype:pdf "{KW}" "receipt"',
    'filetype:pdf "{KW}" "statement"',
    'filetype:doc "{KW}" "confidential"',
    'filetype:txt "{KW}" "password"',
    'filetype:xml "{KW}" "config"',
]

# ─── JS FILES WITH SECRETS ───────────────────────────────────────
js_templates = [
    'filetype:js "api_key" "{KW}"',
    'filetype:js "apiKey" "{KW}"',
    'filetype:js "secret" "{KW}"',
    'filetype:js "token" "{KW}"',
    'filetype:js "checkout" "{KW}"',
    'filetype:js "payment" "{KW}"',
    'filetype:js "firebase" "{KW}"',
    'filetype:js "aws" "key" "{KW}"',
    'filetype:js "merchant" "{KW}"',
    'filetype:js "gateway" "{KW}"',
    'filetype:js "credentials" "{KW}"',
    'filetype:js "authorization" "{KW}"',
]

# ─── MOBILE PAYMENTS / WALLETS ───────────────────────────────────
mobile_templates = [
    'intext:"apple pay" "{KW}"',
    'intext:"google pay" "{KW}"',
    'intext:"samsung pay" "{KW}"',
    'intext:"gpay" "{KW}" "payment"',
    '"digital wallet" "{KW}"',
    '"mobile payment" "{KW}"',
    '"contactless payment" "{KW}"',
    '"tap to pay" "{KW}"',
    '"nfc payment" "{KW}"',
    'intext:"venmo" "{KW}"',
    'intext:"cash app" "{KW}"',
    'intext:"zelle" "{KW}"',
]

# ─── RAW PAYMENT SEARCHES ────────────────────────────────────────
raw_templates = [
    '"{KW}" checkout form site:.com',
    '"{KW}" payment form site:.com',
    '"{KW}" "enter card number"',
    '"{KW}" "credit card form"',
    '"{KW}" "billing information"',
    '"{KW}" "secure checkout"',
    '"{KW}" "process payment"',
    '"{KW}" "accept payments online"',
    '"{KW}" "payment processor"',
    '"{KW}" "card processing"',
    '"{KW}" "merchant account setup"',
    '"{KW}" "online payment gateway"',
    '"{KW}" "recurring billing"',
    '"{KW}" "subscription payment"',
    '"{KW}" "payment integration"',
    '"{KW}" "collect payment"',
    '"{KW}" "payment API"',
    '"{KW}" "charge card"',
    '"{KW}" "refund policy" "payment"',
    '"{KW}" "payment confirmation"',
]

# ─── CRYPTO / ALTERNATIVE PAYMENTS ───────────────────────────────
crypto_templates = [
    'intext:"coinbase" "{KW}" "api"',
    'intext:"bitpay" "{KW}" "token"',
    'intext:"coingate" "{KW}"',
    'intext:"nowpayments" "{KW}"',
    'intext:"btcpay" "{KW}"',
    'intext:"cryptocurrency" "{KW}" "payment"',
    'intext:"bitcoin" "{KW}" "checkout"',
    'intext:"ethereum" "{KW}" "payment"',
    'intext:"USDT" "{KW}" "payment"',
    '"accept crypto" "{KW}"',
    '"crypto payment" "{KW}" "gateway"',
]

# ─── BNPL / FINTECH ─────────────────────────────────────────────
bnpl_templates = [
    'intext:"afterpay" "{KW}"',
    'intext:"clearpay" "{KW}"',
    'intext:"affirm" "{KW}" "payment"',
    'intext:"sezzle" "{KW}"',
    'intext:"zip pay" "{KW}"',
    'intext:"buy now pay later" "{KW}"',
    'intext:"splitit" "{KW}"',
    'intext:"laybuy" "{KW}"',
    'intext:"quadpay" "{KW}"',
    '"installment" "{KW}" "payment"',
    '"pay in 4" "{KW}"',
    '"pay later" "{KW}" "checkout"',
]

# ─── CROSS-KEYWORD COMBOS ───────────────────────────────────────
cross_templates = [
    '"{KW1}" "{KW2}" inurl:checkout',
    '"{KW1}" "{KW2}" inurl:payment',
    '"{KW1}" "{KW2}" inurl:billing',
    '"{KW1}" "{KW2}" filetype:env',
    '"{KW1}" "{KW2}" inurl:admin',
    '"{KW1}" "{KW2}" site:myshopify.com',
    '"{KW1}" "{KW2}" "stripe"',
    '"{KW1}" "{KW2}" "payment gateway"',
    '"{KW1}" "{KW2}" inurl:api',
    '"{KW1}" "{KW2}" filetype:sql',
    '"{KW1}" "{KW2}" inurl:cart',
    '"{KW1}" "{KW2}" "card number"',
    '"{KW1}" "{KW2}" inurl:order',
    '"{KW1}" "{KW2}" inurl:shop',
    '"{KW1}" "{KW2}" filetype:log "payment"',
    '"{KW1}" "{KW2}" "pk_live_"',
    '"{KW1}" "{KW2}" "sk_live_"',
    '"{KW1}" "{KW2}" inurl:invoice',
    '"{KW1}" "{KW2}" inurl:subscribe',
    '"{KW1}" "{KW2}" "paypal"',
]

# ══════════════════════════════════════════════════════════════════
# GENERATE
# ══════════════════════════════════════════════════════════════════

all_single_templates = (
    stripe_templates + paypal_templates + braintree_templates +
    square_templates + adyen_templates + authnet_templates +
    other_gateway_templates + checkout_templates + ecom_templates +
    config_templates + card_data_templates + database_templates +
    admin_templates + api_templates + sqli_templates +
    cloud_templates + directory_templates + js_templates +
    mobile_templates + raw_templates + crypto_templates + bnpl_templates
)

print(f"Single-KW templates: {len(all_single_templates)}")
print(f"Cross-KW templates: {len(cross_templates)}")
print(f"Max single combos: {len(all_single_templates) * len(keywords)}")

dorks = set()

# Phase 1: All single-keyword combos
print("Phase 1: Single-keyword dorks...")
for template in all_single_templates:
    for kw in keywords:
        dork = template.replace("{KW}", kw)
        dorks.add(dork)

print(f"After phase 1: {len(dorks)}")

# Phase 2: Cross-keyword combos if needed
if len(dorks) < TARGET:
    print("Phase 2: Cross-keyword dorks...")
    random.seed(42)
    shuffled_kw = keywords[:]
    random.shuffle(shuffled_kw)
    for template in cross_templates:
        for i in range(0, len(shuffled_kw) - 1, 2):
            kw1 = shuffled_kw[i]
            kw2 = shuffled_kw[i + 1]
            dork = template.replace("{KW1}", kw1).replace("{KW2}", kw2)
            dorks.add(dork)
            dork2 = template.replace("{KW1}", kw2).replace("{KW2}", kw1)
            dorks.add(dork2)
            if len(dorks) >= TARGET:
                break
        if len(dorks) >= TARGET:
            break

print(f"After phase 2: {len(dorks)}")

# Shuffle and trim
dork_list = list(dorks)
random.seed(2026)
random.shuffle(dork_list)
dork_list = dork_list[:TARGET]

output_path = "/home/null/Music/NullIsADork/params/custom_dorks_bot2.txt"
with open(output_path, "w") as f:
    for d in dork_list:
        f.write(d + "\n")

print(f"\nWritten {len(dork_list)} dorks to {output_path}")

# Stats
cats = {
    "Stripe": len([d for d in dork_list if "stripe" in d.lower() or "pk_live" in d or "sk_live" in d or "pk_test" in d or "sk_test" in d or "whsec_" in d]),
    "PayPal": len([d for d in dork_list if "paypal" in d.lower() or "payflow" in d.lower()]),
    "Braintree": len([d for d in dork_list if "braintree" in d.lower()]),
    "Square": len([d for d in dork_list if "square" in d.lower() or "sq0" in d]),
    "Adyen": len([d for d in dork_list if "adyen" in d.lower()]),
    "Authorize.net": len([d for d in dork_list if "authorize" in d.lower()]),
    "Other Gateways": len([d for d in dork_list if any(g in d.lower() for g in ["razorpay","mollie","klarna","worldpay","cybersource","flutterwave","paystack","recurly","moneris","payu","eway","2checkout","gocardless","paddle","bluesnap","paysafe","firstdata","wepay","dwolla","opayo","sagepay","checkout.com","nmi","usaepay","nuvei","heartland","vindicia","bambora","payeezy","iyzico","mercadopago","pagseguro","midtrans","xendit","instamojo","rapyd","chargebee"])]),
    "Checkout/Payment Pages": len([d for d in dork_list if any(p in d for p in ["inurl:checkout","inurl:payment","inurl:billing","inurl:cart","inurl:pay ","inurl:purchase","inurl:donate","inurl:invoice","payment-form","card-details","secure-checkout","pay-now","one-page-checkout","express-checkout","guest-checkout","complete purchase","place order","submit payment","proceed to payment","pay with card"])]),
    "Card/PCI Data": len([d for d in dork_list if any(c in d.lower() for c in ["card_number","cc_num","cardnumber","cardholder","card_cvv","card_exp","4111","card_token","payment_token","pan","billing_cc","payment_card_number"])]),
    "E-commerce": len([d for d in dork_list if any(e in d.lower() for e in ["shopify","woocommerce","magento","prestashop","opencart","bigcommerce","squarespace","gumroad","etsy"])]),
    "Config Leaks": len([d for d in dork_list if "filetype:env" in d or ".env" in d or "config.json" in d or "wp-config" in d or "filetype:yaml" in d or "filetype:yml" in d or "filetype:conf" in d or "filetype:cfg" in d or "filetype:ini" in d or "filetype:properties" in d]),
    "Database/Dumps": len([d for d in dork_list if "filetype:sql" in d or "filetype:csv" in d or "filetype:bak" in d or "filetype:dump" in d or "phpmyadmin" in d or "adminer" in d or "index of" in d]),
    "API Endpoints": len([d for d in dork_list if "inurl:api" in d or "graphql" in d or "swagger" in d or "webhook" in d]),
    "SQLi Params": len([d for d in dork_list if any(s in d for s in ["inurl:id=","inurl:item=","inurl:product_id=","inurl:order_id=","inurl:cat=","inurl:page=","inurl:invoice_id=","inurl:payment_id=","inurl:transaction_id="])]),
    "Cloud Leaks": len([d for d in dork_list if any(c in d for c in ["s3.amazonaws","firebase","blob.core","storage.google","digitalocean","herokuapp","vercel","netlify"])]),
    "JS Secrets": len([d for d in dork_list if "filetype:js" in d]),
    "Mobile/Wallets": len([d for d in dork_list if any(m in d.lower() for m in ["apple pay","google pay","samsung pay","venmo","cash app","zelle","digital wallet","mobile payment","contactless"])]),
    "BNPL/Fintech": len([d for d in dork_list if any(b in d.lower() for b in ["buy now pay later","pay in 4","pay later","sezzle","splitit","laybuy","quadpay","installment","afterpay","clearpay","affirm"])]),
    "Crypto": len([d for d in dork_list if any(c in d.lower() for c in ["coinbase","bitpay","coingate","nowpayments","btcpay","cryptocurrency","bitcoin","ethereum","usdt","crypto payment"])]),
    "Admin Panels": len([d for d in dork_list if "inurl:admin" in d or "inurl:dashboard" in d or "inurl:panel" in d or "wp-admin" in d or "administrator" in d]),
    "Raw Payment": len([d for d in dork_list if any(r in d for r in ["checkout form","payment form","enter card number","credit card form","billing information","process payment","accept payments","payment processor","card processing","merchant account","recurring billing","payment integration","payment API"])]),
}

print("\n=== CATEGORY BREAKDOWN ===")
for cat, count in sorted(cats.items(), key=lambda x: -x[1]):
    pct = count / len(dork_list) * 100
    print(f"  {cat:25s}: {count:>6,}  ({pct:.1f}%)")

# Payment-focused percentage
payment_related = set()
for d in dork_list:
    dl = d.lower()
    if any(x in dl for x in [
        "stripe","paypal","braintree","square","adyen","authorize",
        "payment","checkout","billing","cart","pay","gateway","merchant",
        "card","visa","mastercard","pk_live","sk_live","rzp_","mollie",
        "klarna","worldpay","cybersource","flutterwave","paystack",
        "chargebee","recurly","invoice","receipt","transaction","charge",
        "refund","subscribe","order","purchase","price","buy",
        "coinbase","bitpay","crypto","bitcoin","apple pay","google pay",
        "afterpay","sezzle","affirm","venmo","zelle","shopify","woocommerce",
        "sq0","whsec_","nmi","usaepay","nuvei","bambora","payeezy",
        "iyzico","mercadopago","pagseguro","midtrans","xendit","instamojo"
    ]):
        payment_related.add(d)

pct = len(payment_related) / len(dork_list) * 100
print(f"\n  PAYMENT-RELATED TOTAL   : {len(payment_related):>6,}  ({pct:.1f}%)")
print(f"  NON-PAYMENT (generic)   : {len(dork_list) - len(payment_related):>6,}  ({100-pct:.1f}%)")
