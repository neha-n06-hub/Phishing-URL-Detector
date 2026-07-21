# Phishing-URL-Detector
# 🛡️ Phishing URL Detector

### Machine Learning-Based Phishing URL Detection System

Phishing URL Detector is a machine learning-based cybersecurity application that analyzes the structural and lexical characteristics of URLs to identify whether a URL is **potentially phishing** or **likely legitimate**.

The system uses a **Random Forest Classifier** trained on the **PhiUSIIL Phishing URL Dataset**. It extracts 27 URL-based features without directly visiting or executing the target website, making the detection process fast and safer for preliminary analysis.

The trained machine learning model is integrated into a **Flask web application**, allowing users to enter a URL and receive a classification result along with a confidence score.

---

## Features

- 🔍 URL-based phishing detection
- 🤖 Machine learning classification using Random Forest
- 🧩 Extraction of 27 URL-based features
- 🌐 Flask-based web interface
- 📊 Prediction confidence score
- ⚡ Real-time URL analysis
- 🔒 Static URL analysis without directly visiting the target website
- 📈 Model evaluation using:
  - Accuracy
  - Precision
  - Recall
  - F1-score
  - Confusion Matrix

---

## How It Works

The system follows a machine learning pipeline:

```
                    User Enters URL
                          │
                          ▼
                  Flask Web Application
                          │
                          ▼
                   URL Feature Extraction
                          │
                          ▼
                  27 URL-Based Features
                          │
                          ▼
                Random Forest Classifier
                          │
                          ▼
               Prediction + Confidence Score
                          │
                 ┌────────┴────────┐
                 │                 │
                 ▼                 ▼
        Potential Phishing    Likely Legitimate
              URL                   URL
