import streamlit as st
import pandas as pd
import numpy as np
import joblib
import re
from urllib.parse import urlparse
from collections import Counter

# Load the trained model
model = joblib.load('XGBoost_model.pkl')

def entropy(s):
    p, lns = Counter(s), float(len(s))
    return -sum(count / lns * np.log2(count / lns) for count in p.values())

def extract_features(url):
    features = {}

    # URL Length
    features['url_length'] = len(url)

    # Number of Dots
    features['num_dots'] = url.count('.')

    # Number of Hyphens
    features['num_hyphens'] = url.count('-')

    # Number of Digits
    features['num_digits'] = sum(c.isdigit() for c in url)

    # Presence of IP Address
    features['presence_of_ip'] = int(bool(re.search(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', url)))

    # Number of Subdomains
    parsed_url = urlparse(url)
    subdomain = parsed_url.hostname.split('.')[:-2] if parsed_url.hostname else []
    features['num_subdomains'] = len(subdomain)

    # Presence of Suspicious Words
    suspicious_words = ['login', 'update', 'free', 'security', 'webscr', 'ebayisapi', 'signin']
    features['presence_of_suspicious_words'] = int(any(word in url for word in suspicious_words))

    # Number of Parameters
    features['num_parameters'] = len(parsed_url.query.split('&')) if parsed_url.query else 0

    # Presence of HTTPS
    features['presence_of_https'] = int(parsed_url.scheme == 'https')

    # Length of Query String
    features['length_of_query_string'] = len(parsed_url.query)

    # Presence of Encoded Characters
    features['presence_of_encoded_characters'] = int('%' in url)

    # Presence of Suspicious TLDs
    suspicious_tlds = ['.xyz', '.top', '.info', '.loan', '.club']
    features['presence_of_suspicious_tlds'] = int(any(url.endswith(tld) for tld in suspicious_tlds))

    # Presence of Brand Names (example list, needs customization based on use case)
    brand_names = ['apple', 'google', 'paypal', 'microsoft', 'amazon']
    features['presence_of_brand_names'] = int(any(brand in url for brand in brand_names))

    # Length of Domain Name
    domain = parsed_url.hostname
    features['length_of_domain_name'] = len(domain) if domain else 0

    # Number of Directory Levels
    features['num_directory_levels'] = url.count('/')

    # Ratio of Digits to Characters
    total_chars = len(url)
    num_digits = features['num_digits']
    features['ratio_digits_to_chars'] = num_digits / total_chars if total_chars > 0 else 0

    # Presence of Non-ASCII Characters
    features['presence_of_non_ascii'] = int(any(ord(c) > 127 for c in url))

    # Presence of @ Symbol
    features['presence_of_at_symbol'] = int('@' in url)

    # Presence of Redirection (//)
    features['presence_of_redirection'] = int('//' in url[8:])  # Ignore 'http://' or 'https://'

    # URL Entropy
    features['url_entropy'] = entropy(url)

    return features

def main():
    st.title("Malicious URL Detection")
    st.write("Enter a URL to check if it is malicious or not.")

    # Input URL
    input_url = st.text_input("Enter URL")

    if st.button("Predict"):
        if input_url:
            features = extract_features(input_url)
            features_df = pd.DataFrame([features])
            prediction = model.predict(features_df)[0]
            prediction_proba = model.predict_proba(features_df)[0]

            if prediction == 1:
                st.error(f"The URL is predicted to be malicious with a probability of {prediction_proba[1]:.2f}")
            else:
                st.success(f"The URL is predicted to be safe with a probability of {prediction_proba[0]:.2f}")
        else:
            st.error("Please enter a valid URL")

if __name__ == "__main__":
    main()
