FROM python:3.12-slim

WORKDIR /app
COPY . .
RUN pip install -e .

# Run the report, THEN start a sleep loop to keep the container alive
CMD ["sh", "-c", "secureai report && tail -f /dev/null"]
