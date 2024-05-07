# 
FROM python:slim

#
RUN apt-get update && \
    apt-get install -y libpq-dev gcc

# 
WORKDIR /app

# 
COPY requirements.txt .

# 
RUN pip install -r requirements.txt

# 
COPY . .

# 
RUN python3 aes_encrypt.py

#
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8082"]