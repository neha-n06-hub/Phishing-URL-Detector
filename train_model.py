import pandas as pd
import joblib
import os

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix
)

from url_features import extract_url_features


print("======================================")
print("PHISHING URL DETECTOR - MODEL TRAINING")
print("======================================")

# ==========================================
# STEP 1: LOAD DATASET
# ==========================================

print("\nLoading dataset...")

df = pd.read_csv(
    "PhiUSIIL_Phishing_URL_Dataset.csv",
    low_memory=False
)

print("Dataset loaded successfully!")

print(
    f"Total URLs: {len(df)}"
)

# ==========================================
# STEP 2: CHECK LABEL DISTRIBUTION
# ==========================================

print("\nLabel distribution:")

print(
    df["label"].value_counts()
)

# ==========================================
# STEP 3: EXTRACT URL FEATURES
# ==========================================

print("\nExtracting URL features...")

feature_rows = []

total_rows = len(df)

for index, url in enumerate(df["URL"]):

    try:

        features = extract_url_features(
            str(url)
        )

        feature_rows.append(
            features
        )

    except Exception as e:

        print(
            f"Error processing URL at row {index}: {e}"
        )

        feature_rows.append(
            {}
        )

    # Progress every 10,000 URLs
    if (
        index + 1
    ) % 10000 == 0:

        print(
            f"Processed {index + 1} / {total_rows} URLs"
        )


# Convert features to DataFrame
X = pd.DataFrame(
    feature_rows
)

# Target labels
y = df["label"]


print("\nFeature extraction completed!")

print(
    f"Number of features: {X.shape[1]}"
)

print(
    f"Number of samples: {X.shape[0]}"
)


# ==========================================
# STEP 4: DISPLAY FEATURES
# ==========================================

print("\nFeatures used:")

for feature in X.columns:

    print(
        "-",
        feature
    )


# ==========================================
# STEP 5: TRAIN / TEST SPLIT
# ==========================================

print("\nSplitting dataset...")

X_train, X_test, y_train, y_test = train_test_split(

    X,

    y,

    test_size=0.20,

    random_state=42,

    stratify=y
)


print(
    f"Training samples: {len(X_train)}"
)

print(
    f"Testing samples: {len(X_test)}"
)


# ==========================================
# STEP 6: TRAIN RANDOM FOREST
# ==========================================

print("\nTraining Random Forest model...")

model = RandomForestClassifier(

    n_estimators=200,

    max_depth=None,

    random_state=42,

    n_jobs=-1
)


model.fit(

    X_train,

    y_train
)


print(
    "Model training completed!"
)


# ==========================================
# STEP 7: TEST MODEL
# ==========================================

print("\nEvaluating model...")

predictions = model.predict(
    X_test
)


# ==========================================
# STEP 8: ACCURACY
# ==========================================

accuracy = accuracy_score(

    y_test,

    predictions
)


print("\n======================================")

print(

    f"Model Accuracy: "
    f"{accuracy * 100:.2f}%"

)

print("======================================")


# ==========================================
# STEP 9: CLASSIFICATION REPORT
# ==========================================

print("\nClassification Report:")

print(

    classification_report(

        y_test,

        predictions

    )

)


# ==========================================
# STEP 10: CONFUSION MATRIX
# ==========================================

print("\nConfusion Matrix:")

print(

    confusion_matrix(

        y_test,

        predictions

    )

)


# ==========================================
# STEP 11: SAVE MODEL
# ==========================================

print("\nSaving model...")

os.makedirs(

    "model",

    exist_ok=True

)


joblib.dump(

    model,

    "model/phishing_model.pkl"

)


# ==========================================
# STEP 12: SAVE FEATURE NAMES
# ==========================================

feature_names = list(
    X.columns
)


joblib.dump(

    feature_names,

    "model/feature_names.pkl"

)


print("\n======================================")

print("MODEL SAVED SUCCESSFULLY!")

print(
    "Location: model/phishing_model.pkl"
)

print(
    "Features: model/feature_names.pkl"
)

print("======================================")