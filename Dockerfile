FROM python:3.11.7-slim

# Copy the dependencies file to the working directory
COPY requirements.txt .

# Install any dependencies
RUN pip install --no-cache-dir -r requirements.txt


COPY mutate_affinity.py /mutate_affinity.py

EXPOSE 5050

CMD ["python", "/mutate_affinity.py"]