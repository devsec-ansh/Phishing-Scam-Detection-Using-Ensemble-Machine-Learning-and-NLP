import joblib,os
import feature_extraction
import numpy as np
from array import array

phish_model = open(r'C:\Users\Acer\Desktop\Machine Learning Models\Phishing Detection Using ML\phishingURL.pkl', 'rb')
phish_model_ls = joblib.load(phish_model)

X_predict = []
X_input=input("Enter URL : ")
X_predict=feature_extraction.feature_dataset(X_input)
X_predict = np.array(X_predict).reshape(1,-1)
y_Predict = phish_model_ls.predict(X_predict)
if y_Predict == 1:
	result = "This is a Phishing Site"
else:
	result = "This is not a Phishing Site"
print(result)