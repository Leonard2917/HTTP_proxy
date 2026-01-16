import threading
import requests

# Configurează proxy-ul tău aici
proxies = {
    "http": "http://127.0.0.1:8888",
    "https": "http://127.0.0.1:8888",
}

def send_request(id):
    try:
        # Testăm pe endpoint-ul de cookies
        response = requests.get("http://httpbin.org/cookies", proxies=proxies, timeout=5)
        print(f"Cererea {id}: Status {response.status_code}")
    except Exception as e:
        print(f"Cererea {id} a eșuat: {e}")

# Lansăm 50 de thread-uri simultan
threads = []
for i in range(50):
    t = threading.Thread(target=send_request, args=(i,))
    threads.append(t)
    t.start()

for t in threads:
    t.join()