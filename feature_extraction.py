import configparser
import requests
import json

from urllib import parse
import urllib
from dns import resolver, reversename
from datetime import datetime
from bs4 import BeautifulSoup
from rblwatch import RBLSearch
import re
import whois
import ipaddress
import requests
from urllib.parse import urlparse
from tldextract import extract
import tldextract
import re
import os
from django.core.validators import URLValidator
import requests
import socket

def feature_dataset(url):
  data_set=[]

  # if not re.match(r"^https?", url):
  #   url = "http://" + url

#1
  if len(url)<=37:
    data_set.append(0)
  else:
    data_set.append(1)

#2
  dot_count = url.count('.')
  data_set.append(dot_count)

#3
  slash_count = url.count('/')
  data_set.append(slash_count)

#4
  hyphen_count = url.count('-')
  data_set.append(hyphen_count)

#5
  at_count = url.count('@')
  data_set.append(at_count)

#6
  underline_count = url.count('_')
  data_set.append(underline_count)

#7
  plus_count = url.count('+')
  data_set.append(plus_count)

#8
  hashtag_count = url.count('#')
  data_set.append(hashtag_count)

#9
  digit_count = 0
  for i in url:
    if i.isdigit():
      digit_count=digit_count+1
  data_set.append(digit_count)

#10
  special=0
  for i in url:
    if(url.isalpha()==0 and url.isdigit()==0):
      special = special + 1
  data_set.append(special)

#11
  percentage_count = url.count('%')
  data_set.append(percentage_count)

#12
  equal_count = url.count('=')
  data_set.append(equal_count)   

#13
  and_count = url.count('&')
  data_set.append(and_count)

#14
  question_count = url.count('?')
  data_set.append(question_count)

#15
  doubleSlash_count = url.count('//')
  data_set.append(doubleSlash_count)

#16
  uppercase_count=0
  for i in url:
    if i.isupper():
      uppercase_count=uppercase_count+1
  data_set.append(uppercase_count)
    
#17
  try:
    uppercase_count = 0
    for i in url:
      if i.isupper():
        uppercase_count=uppercase_count+1
    uppercaseRatio=(int)(len(url)/uppercase_count)
    data_set.append(uppercaseRatio)
  except:
    data_set.append(0)

#18
  try:
    digit_count = 0
    for i in url:
      if i.isdigit():
        digit_count=digit_count+1
    digitRatio=(int)(len(url)/digit_count)
    data_set.append(digitRatio)
  except:
    data_set.append(0)
    
#19
  if '%20' in url:
      data_set.append(0)
  else:
      data_set.append(1)

  #Domain Based Features

  domain=urlparse(url).netloc

#20
  if len(domain)<=8:
    data_set.append(0)
  elif len(domain)>=9 and len(domain)<=16:
    data_set.append(1)
  elif len(domain)>=17 and len(domain)<=24:
    data_set.append(2)
  else:
    data_set.append(3)

#21
  subdomain = tldextract.extract(url).subdomain
  data_set.append(len(subdomain))

#22
  domainDigit_count = 0
  for i in domain:
    if i.isdigit():
      domainDigit_count=domainDigit_count+1
  data_set.append(domainDigit_count)

#23
  scheme = urlparse(url).scheme
  if scheme == 'https':
    data_set.append(0)
  else:
    data_set.append(1)
    
#24
  domainDots_count = domain.count('.')
  data_set.append(domainDots_count)

#25
  vowels=0
  for i in domain:
    if(i=='a' or i=='e' or i=='i' or i=='o' or i=='u' or i=='A' or i=='E' or i=='I' or i=='O' or i=='U'):
      vowels=vowels+1
  data_set.append(vowels)
    
#26
  if '-' in domain:
    data_set.append(1)
  else:
    data_set.append(0)

#27
  tsd, td, tsu = extract(url) # gets subdomain, domain, tld
  if tsu==".com":
    data_set.append(73)
  elif tsu==".ac.in":
    data_set.append(5)
  else:
    data_set.append(0)

#28
  subdomain = tldextract.extract(url).subdomain
  if subdomain=="www":
    data_set.append(2178)
  else:
    data_set.append(0)

#29
  port = urlparse(url).port
  if port=="NaN":
    data_set.append(6)
  else:
    data_set.append(0)

  # DIRECTORY/PARAMETERS BASED FEATURES

  query=urlparse(url).query
  path=urlparse(url).path

#30
  if path:
    data_set.append(1)
  else:
    data_set.append(0)

#31
  heirarchycount=0
  for i in path:
    if i=='/':
      heirarchycount=heirarchycount+1
  if heirarchycount<=11:
    data_set.append(heirarchycount)
  else:
    data_set.append(12)

#32
  pathSlash_count = path.count('/')
  data_set.append(pathSlash_count)

#33
  pathHyphencount = path.count('-')
  data_set.append(pathHyphencount)

#34
  pathdigitscount=0
  for i in path:
    if i.isdigit():
      pathdigitscount=pathdigitscount+1
  data_set.append(pathdigitscount)

#35
  pathPercentagecount = path.count('%')
  data_set.append(pathPercentagecount)

#36
  extension = os.path.splitext(path)[1]
  if len(extension)<=3:
    data_set.append(1)
  elif len(extension)>=3 and len(extension)<=8:
    data_set.append(2)
  else:
    data_set.append(0) 

#37
  if query:
    data_set.append(1)
  else:
    data_set.append(0)

#38
  if len(query)<10:
    data_set.append(0)
  elif len(query)>=11 and len(query)<=20:
    data_set.append(1)
  elif len(query)>=21 and len(query)<=30:
    data_set.append(2)
  else:
    data_set.append(3)

#39
  if '-' in query:
    data_set.append(0)           
  else:
    data_set.append(1)

#40
  queryEqualcount = query.count('=')
  data_set.append(queryEqualcount)

#41
  queryAtcount = query.count('@')
  data_set.append(queryAtcount)

#42
  queryDigitcount = 0
  for i in query:
    if i.isdigit():
      queryDigitcount=queryDigitcount +1
  data_set.append(queryDigitcount)

#43
  try:
    digit_count = 0
    for i in query:
      if i.isdigit():
        digit_count=digit_count+1
    data_set.append((int)(len(query)/digit_count))
  except:
    data_set.append(0)
  
#44
  default="null"
  extension = os.path.splitext(path)[1]
  if extension==".php":
    data_set.append(54)
  else:
    data_set.append(76)

#45
  url_shortners = r"bit\.ly|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|x\.co|prettylinkpro\.com|scrnch\.me|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|yfrog\.com|migre\.me|kl\.am|wp\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|" \
  r"short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|doiop\.com|short\.ie|qr\.net|1url\.com|tweez\.me|v\.gd|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|db\.tt|" \
  r"qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|q\.gs|is\.gd|po\.st|filoops\.info|vzturl\.com|tr\.im|link\.zip\.net"
  value=re.search(url_shortners,url)
  if value:
    data_set.append(1)
  else:
    data_set.append(0)

#46
  redirect = url.rfind('//')
  if redirect > 6:
    if redirect > 7:
      data_set.append(1)
    else:
      data_set.append(0)
  else:
    data_set.append(0)

#47
  value=re.findall(r'[\w\.-]+@[\w\.-]+', url)
  if value:
    data_set.append(1)
  else:
    data_set.append(0)

#48
  try:
    validate = URLValidator()
    validate(url)
    data_set.append(1)
  except:
    data_set.append(0)
  
#49
  try:
    ip_add=socket.gethostbyname(domain)
    ip_add = ip_add.split(".")
    ip_class = [int(i) for i in ip_add]
    if ip_class[0]>=0 and ip_class[0]<128:
      data_set.append(1)
    elif ip_class[0]>=128 and ip_class[0]<192:
      data_set.append(2)
    elif ip_class[0]>=192 and ip_class[0]<224:
      data_set.append(3)
    elif ip_class[0]>=224 and ip_class[0]<240:
      data_set.append(4)
    else:
      data_set.append(5)
  except:
      data_set.append(0)

#50
  dns = 0
  try:
    domain_name = whois.whois(domain)
  except:
    dns = 1
  try:
    if dns==0:    
      created = domain_name.creation_date
      expiry = domain_name.expiration_date
      if (isinstance(created,str) or isinstance(expiry,str)):
        try:
          created = datetime.strptime(created,'%Y-%m-%d')
          expiry = datetime.strptime(expiry,"%Y-%m-%d")
        except:
          data_set.append(1)
      ageofdomain = abs((expiry - created).days)
      if (ageofdomain < 180):
        age = 1
      else:
        age = 0
        return age
    else:
      data_set.append(2)
  except:
    data_set.append(3)

  return data_set

# url="https://towardsdatascience.com/how-to-deploy-machine-learning-models-as-a-microservice-using-fastapi-b3a6002768af"
# X_predict = []
# X_input=url
# X_predict=feature_dataset(url)
# print(X_predict)