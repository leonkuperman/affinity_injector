FROM python:3.11.7-slim
RUN pip install flask
COPY mutate_affinity.py /mutate_affinity.py
COPY tls.crt /tls.crt
COPY tls.key /tls.key
EXPOSE 5050
CMD ["python", "/mutate_affinity.py"]