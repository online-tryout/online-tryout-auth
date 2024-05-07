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
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8082"]