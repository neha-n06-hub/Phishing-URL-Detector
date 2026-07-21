from flask import Flask, render_template, request
import joblib
import pandas as pd

from url_features import extract_url_features


app = Flask(__name__)


# ==========================================
# LOAD TRAINED MODEL
# ==========================================

model = joblib.load(
    "model/phishing_model.pkl"
)

feature_names = joblib.load(
    "model/feature_names.pkl"
)


# ==========================================
# HOME PAGE
# ==========================================

@app.route("/")
def home():

    return render_template(
        "index.html"
    )


# ==========================================
# CHECK URL
# ==========================================

@app.route(
    "/predict",
    methods=["POST"]
)
def predict():

    url = request.form.get(
        "url",
        ""
    ).strip()


    # ======================================
    # CHECK EMPTY URL
    # ======================================

    if not url:

        return render_template(

            "index.html",

            prediction="Please enter a URL."

        )


    # ======================================
    # ADD HTTPS IF MISSING
    # ======================================

    if not url.startswith(
        ("http://", "https://")
    ):

        url = "https://" + url


    try:

        # ==================================
        # EXTRACT FEATURES
        # ==================================

        features = extract_url_features(
            url
        )


        # ==================================
        # CONVERT TO DATAFRAME
        # ==================================

        feature_data = pd.DataFrame(

            [[
                features[name]
                for name in feature_names
            ]],

            columns=feature_names

        )


        # ==================================
        # PREDICT
        # ==================================

        prediction = model.predict(
            feature_data
        )[0]


        # ==================================
        # GET PROBABILITY
        # ==================================

        probabilities = model.predict_proba(

            feature_data

        )[0]


        confidence = (

            max(probabilities)

            * 100

        )


        # ==================================
        # LABEL MAPPING
        # ==================================

        # Based on the PhiUSIIL dataset:
        #
        # 0 = Phishing
        # 1 = Legitimate

        if prediction == 0:

            result = "Potential Phishing URL"

            status = "phishing"

        else:

            result = "Likely Legitimate URL"

            status = "legitimate"


        # ==================================
        # SEND RESULT TO HTML
        # ==================================

        return render_template(

            "index.html",

            prediction=result,

            status=status,

            confidence=f"{confidence:.2f}",

            checked_url=url

        )


    except Exception as e:

        return render_template(

            "index.html",

            prediction=f"Error: {str(e)}"

        )


# ==========================================
# RUN APPLICATION
# ==========================================

if __name__ == "__main__":

    app.run(

        debug=True

    )