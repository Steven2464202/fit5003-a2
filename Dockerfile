FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
EXPOSE 5000
# Set your student ID so it appears on every page (personalises your screenshots/video).
ENV STUDENT_ID=set-STUDENT_ID
CMD ["python", "app.py"]
