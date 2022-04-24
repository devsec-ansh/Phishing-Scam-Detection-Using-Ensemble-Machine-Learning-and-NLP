import numpy as np
import pandas as pa
from flask import Flask, jsonify, request, render_template
from sklearn.pipeline import Pipeline 
import feature_extraction
import pickle
from sklearn.feature_extraction.text import CountVectorizer,TfidfVectorizer
from sklearn.pipeline import Pipeline
from nltk.corpus import stopwords


phishing_model = pickle.load(open(r'C:\Users\Acer\Desktop\Machine Learning Models\Phishing Detection Using ML\phishingURL.pkl', 'rb'))

spam_model = pickle.load(open(r'C:\Users\Acer\Desktop\Machine Learning Models\Email Spam Detection Using ML\SpamEmailDetection.pkl', 'rb'))

cv = pickle.load(open(r'C:\Users\Acer\Desktop\Machine Learning Models\Email Spam Detection Using ML\transform.pkl','rb'))

app = Flask(__name__)

@app.route("/")
def Home():
  return render_template("index.html")

@app.route("/predicturl", methods=['GET', 'POST'])
def predicturl():
  X_input = request.args.get('url')
  X_predict = []
  X_predict=feature_extraction.feature_dataset(str(X_input))
  features=[np.array(X_predict)]
  url_prediction = phishing_model.predict(features)

  if url_prediction == 1:
    text = "This is a Phishing Site"
  else:
    text = "This is not a Phishing Site"

  return render_template("index.html", prediction_text="{}".format(text))

import re
from nltk.corpus import stopwords
from nltk.stem.porter import PorterStemmer
from nltk.stem import SnowballStemmer
snowball_stemmer = SnowballStemmer("english")
porter_stemmer = PorterStemmer()

from sklearn.feature_extraction.text import CountVectorizer, TfidfTransformer, TfidfVectorizer

from nltk.tokenize import RegexpTokenizer
from nltk.stem.wordnet import WordNetLemmatizer

stop_words=stopwords.words("english")

@app.route("/predictspam", methods=['GET', 'POST'])
def predictspam():
  msg = request.form["spam"]
  data=[msg]
  vect=cv.transform(data).toarray()
  text_prediction = spam_model.predict(vect)

  if text_prediction == 1:
    text = "This is a spam email"
  else:
    text = "This is not an spam email"

  return render_template("index.html", spam_text="{}".format(text))

if __name__=="__main__":
  app.run(debug=True)