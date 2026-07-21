import pandas as pd
import joblib
import re
from urllib.parse import urlparse

print("Loading model...")

# Load trained model
model = joblib.load("model/phishing_model.pkl")

# Load feature names
feature_names = joblib.load("model/feature_names.pkl")

print("Loading dataset...")

# Load dataset
df = pd.read_csv(
    "PhiUSIIL_Phishing_URL_Dataset.csv",
    low_memory=False
)

print("\nModel loaded successfully!")
print("Dataset loaded successfully!")

print("\n===================================")
print("DATASET LABEL DISTRIBUTION")
print("===================================")

print(df["label"].value_counts())


# ==========================================
# FEATURE EXTRACTION
# ==========================================

def extract_features(url):

    parsed = urlparse(url)

    domain = parsed.netloc

    hostname = parsed.hostname or ""

    # 1. URL Length
    url_length = len(url)

    # 2. Domain Length
    domain_length = len(domain)

    # 3. Is Domain IP
    is_domain_ip = 1 if re.match(
        r"^(?:\d{1,3}\.){3}\d{1,3}$",
        hostname
    ) else 0

    # 4. Number of Subdomains
    domain_parts = hostname.split(".")

    no_of_subdomain = max(
        0,
        len(domain_parts) - 2
    )

    # 5. Has Obfuscation
    has_obfuscation = 1 if (
        "@" in url or
        "%" in url
    ) else 0

    # 6. Number of Obfuscated Characters
    no_of_obfuscated_char = (
        url.count("@") +
        url.count("%")
    )

    # 7. Number of Letters
    no_of_letters = sum(
        char.isalpha()
        for char in url
    )

    # 8. Number of Digits
    no_of_digits = sum(
        char.isdigit()
        for char in url
    )

    # 9. Number of =
    no_of_equals = url.count("=")

    # 10. Number of ?
    no_of_question = url.count("?")

    # 11. Number of &
    no_of_ampersand = url.count("&")

    # 12. Other Special Characters
    special_characters = "~!#$%^*()_+{}[]|\\:;'<>,"

    no_of_other_special = sum(
        char in special_characters
        for char in url
    )

    # 13. HTTPS
    is_https = 1 if (
        parsed.scheme.lower() == "https"
    ) else 0

    data = {

        "URLLength":
            url_length,

        "DomainLength":
            domain_length,

        "IsDomainIP":
            is_domain_ip,

        "NoOfSubDomain":
            no_of_subdomain,

        "HasObfuscation":
            has_obfuscation,

        "NoOfObfuscatedChar":
            no_of_obfuscated_char,

        "NoOfLettersInURL":
            no_of_letters,

        "NoOfDegitsInURL":
            no_of_digits,

        "NoOfEqualsInURL":
            no_of_equals,

        "NoOfQMarkInURL":
            no_of_question,

        "NoOfAmpersandInURL":
            no_of_ampersand,

        "NoOfOtherSpecialCharsInURL":
            no_of_other_special,

        "IsHTTPS":
            is_https
    }

    # Keep exact feature order
    features = pd.DataFrame(
        [[
            data[feature]
            for feature in feature_names
        ]],
        columns=feature_names
    )

    return features


# ==========================================
# TEST DATASET URLS
# ==========================================

print("\n===================================")
print("TESTING REAL DATASET URLS")
print("===================================")


# Get 10 URLs with label 0
label_0_data = df[
    df["label"] == 0
].head(10)


# Get 10 URLs with label 1
label_1_data = df[
    df["label"] == 1
].head(10)


# ==========================================
# TEST LABEL 0
# ==========================================

print("\n\n========== LABEL 0 TESTS ==========")

for index, row in label_0_data.iterrows():

    url = row["URL"]

    actual_label = row["label"]

    features = extract_features(url)

    prediction = model.predict(
        features
    )[0]

    probabilities = model.predict_proba(
        features
    )[0]

    confidence = max(
        probabilities
    ) * 100

    print("\nURL:", url)

    print(
        "Actual Label:",
        actual_label
    )

    print(
        "Model Prediction:",
        prediction
    )

    print(
        "Confidence:",
        f"{confidence:.2f}%"
    )


# ==========================================
# TEST LABEL 1
# ==========================================

print("\n\n========== LABEL 1 TESTS ==========")

for index, row in label_1_data.iterrows():

    url = row["URL"]

    actual_label = row["label"]

    features = extract_features(url)

    prediction = model.predict(
        features
    )[0]

    probabilities = model.predict_proba(
        features
    )[0]

    confidence = max(
        probabilities
    ) * 100

    print("\nURL:", url)

    print(
        "Actual Label:",
        actual_label
    )

    print(
        "Model Prediction:",
        prediction
    )

    print(
        "Confidence:",
        f"{confidence:.2f}%"
    )


print("\n===================================")
print("TEST COMPLETE")
print("===================================")