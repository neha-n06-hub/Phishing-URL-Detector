import re
import math
import ipaddress
from urllib.parse import urlparse


# ==========================================
# SUSPICIOUS KEYWORDS
# ==========================================

SUSPICIOUS_KEYWORDS = [
    "login",
    "signin",
    "verify",
    "verification",
    "account",
    "update",
    "secure",
    "security",
    "bank",
    "paypal",
    "password",
    "confirm",
    "confirmation",
    "credential",
    "wallet",
    "payment",
    "invoice",
    "free",
    "bonus",
    "prize",
    "winner",
    "claim",
    "urgent",
    "alert",
    "suspend",
    "suspended",
    "unlock",
    "recover",
    "reset"
]


# ==========================================
# CHECK IP ADDRESS
# ==========================================

def is_ip_address(hostname):

    try:

        ipaddress.ip_address(hostname)

        return 1

    except ValueError:

        return 0


# ==========================================
# CALCULATE ENTROPY
# ==========================================

def calculate_entropy(text):

    if not text:

        return 0

    probabilities = []

    for char in set(text):

        probability = (
            text.count(char) / len(text)
        )

        probabilities.append(
            probability
        )

    entropy = 0

    for probability in probabilities:

        entropy -= (
            probability *
            math.log2(probability)
        )

    return entropy


# ==========================================
# EXTRACT URL FEATURES
# ==========================================

def extract_url_features(url):

    parsed = urlparse(url)

    hostname = parsed.hostname or ""

    domain = parsed.netloc

    path = parsed.path

    query = parsed.query

    url_lower = url.lower()

    # Remove port from domain
    hostname_without_port = hostname.split(":")[0]


    # ======================================
    # BASIC FEATURES
    # ======================================

    url_length = len(url)

    domain_length = len(hostname)

    path_length = len(path)

    query_length = len(query)


    # ======================================
    # CHARACTER COUNTS
    # ======================================

    number_of_digits = sum(
        char.isdigit()
        for char in url
    )

    number_of_letters = sum(
        char.isalpha()
        for char in url
    )

    number_of_dots = url.count(".")

    number_of_hyphens = url.count("-")

    number_of_underscores = url.count("_")

    number_of_slashes = url.count("/")

    number_of_question_marks = url.count("?")

    number_of_equals = url.count("=")

    number_of_ampersands = url.count("&")

    number_of_at_symbols = url.count("@")

    number_of_percent_symbols = url.count("%")


    # ======================================
    # SUBDOMAIN COUNT
    # ======================================

    domain_parts = hostname.split(".")

    number_of_subdomains = max(
        0,
        len(domain_parts) - 2
    )


    # ======================================
    # IP ADDRESS
    # ======================================

    has_ip = is_ip_address(
        hostname_without_port
    )


    # ======================================
    # HTTPS
    # ======================================

    is_https = 1 if (
        parsed.scheme.lower() == "https"
    ) else 0


    # ======================================
    # SUSPICIOUS KEYWORDS
    # ======================================

    suspicious_keyword_count = 0

    for keyword in SUSPICIOUS_KEYWORDS:

        if keyword in url_lower:

            suspicious_keyword_count += 1


    # ======================================
    # OBFUSCATION
    # ======================================

    has_at_symbol = 1 if "@" in url else 0

    has_percent_encoding = 1 if "%" in url else 0

    has_double_slash = 1 if (
        "//" in path
    ) else 0


    # ======================================
    # DOMAIN CHARACTERISTICS
    # ======================================

    has_hyphen_in_domain = 1 if (
        "-" in hostname
    ) else 0

    has_many_subdomains = 1 if (
        number_of_subdomains >= 3
    ) else 0


    # ======================================
    # URL ENTROPY
    # ======================================

    url_entropy = calculate_entropy(
        url
    )


    # ======================================
    # DIGIT RATIO
    # ======================================

    if url_length > 0:

        digit_ratio = (
            number_of_digits /
            url_length
        )

    else:

        digit_ratio = 0


    # ======================================
    # SPECIAL CHARACTER RATIO
    # ======================================

    special_characters = (
        number_of_dots +
        number_of_hyphens +
        number_of_underscores +
        number_of_slashes +
        number_of_question_marks +
        number_of_equals +
        number_of_ampersands +
        number_of_at_symbols +
        number_of_percent_symbols
    )

    if url_length > 0:

        special_character_ratio = (
            special_characters /
            url_length
        )

    else:

        special_character_ratio = 0


    # ======================================
    # CREATE FEATURE DICTIONARY
    # ======================================

    features = {

        "url_length":
            url_length,

        "domain_length":
            domain_length,

        "path_length":
            path_length,

        "query_length":
            query_length,

        "number_of_digits":
            number_of_digits,

        "number_of_letters":
            number_of_letters,

        "number_of_dots":
            number_of_dots,

        "number_of_hyphens":
            number_of_hyphens,

        "number_of_underscores":
            number_of_underscores,

        "number_of_slashes":
            number_of_slashes,

        "number_of_question_marks":
            number_of_question_marks,

        "number_of_equals":
            number_of_equals,

        "number_of_ampersands":
            number_of_ampersands,

        "number_of_at_symbols":
            number_of_at_symbols,

        "number_of_percent_symbols":
            number_of_percent_symbols,

        "number_of_subdomains":
            number_of_subdomains,

        "has_ip":
            has_ip,

        "is_https":
            is_https,

        "suspicious_keyword_count":
            suspicious_keyword_count,

        "has_at_symbol":
            has_at_symbol,

        "has_percent_encoding":
            has_percent_encoding,

        "has_double_slash":
            has_double_slash,

        "has_hyphen_in_domain":
            has_hyphen_in_domain,

        "has_many_subdomains":
            has_many_subdomains,

        "url_entropy":
            url_entropy,

        "digit_ratio":
            digit_ratio,

        "special_character_ratio":
            special_character_ratio
    }


    return features