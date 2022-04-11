import flask
import io
import string
import time
import os, joblib
import numpy as np
from flask import Flask, jsonify, request, render_template 
import feature_extraction
import pickle

model = pickle.load(open(r'C:\Users\Acer\Desktop\Machine Learning Models\Phishing Detection Using ML\phishingURL.pkl', 'rb'))
# phish_model_ls = joblib.load(phish_model)

app = Flask(__name__)

@app.route("/")
def Home():
  return render_template("index.html")

@app.route("/predict", methods=['GET', 'POST'])
def predict():
  X_input = request.args.get('url')
  X_predict = []
  X_predict=feature_extraction.feature_dataset(str(X_input))
  features=[np.array(X_predict)]
  prediction = model.predict(features)

  return render_template("index.html", prediction_text="This URL status is {}".format(prediction))

if __name__=="__main__":
  app.run(debug=True)