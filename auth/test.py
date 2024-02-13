from dotenv import load_dotenv, find_dotenv
import os
from jose import JWTError, jwt

load_dotenv(find_dotenv())

SECRET_KEY = os.environ.get('SECRET_KEY')
ALGORITHM = os.environ.get('ALGORITHM')

token='eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOlsiam9obmRvZSJdLCJleHAiOjE3MDc4MzU5NjN9.F9X81pikN5k8s6OslOQXgWko5JN2wubCiaF-Na7LMvY'


#payload = jwt.decode(jwt=token, key=SECRET_KEY, algorithms=["HS256"])
payload = jwt.decode(token=token, key=SECRET_KEY, algorithms=["HS256"])
print(payload)


