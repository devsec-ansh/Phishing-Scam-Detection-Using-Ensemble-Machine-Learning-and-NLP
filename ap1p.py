from fastapi import FastAPI
import uvicorn
import joblib,os
import feature_extraction
import numpy as np
from flask import Flask, jsonify, request

app = FastAPI()


#pkl
phish_model = open(r'C:\Users\Acer\Desktop\Machine Learning Models\Phishing Detection Using ML\phishingURL.pkl', 'rb')
phish_model_ls = joblib.load(phish_model)


@app.get("/")
async def root():
  return {"message": "Hello World"}

# ML Aspect
@app.post('/predict/{url}')
async def predict(url):
	X_predict = []
	X_input=url
	X_predict=feature_extraction.feature_dataset(X_input)
	X_predict = np.array(X_predict).reshape(1,-1)
	y_Predict = phish_model_ls.predict(X_predict)
	if y_Predict == 1:
		result = "This is a Phishing Site"
	else:
		result = "This is not a Phishing Site"

	return (jsonify(X_predict,result))

if __name__ == '__main__':
	uvicorn.run(app,host="127.0.0.1",port=8000)