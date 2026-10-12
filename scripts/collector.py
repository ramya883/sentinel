import time
import sys
import psutil
import requests

API_URL = "http://localhost:5000/api"
EMAIL = "admin@sentinel.local"
USERNAME = "admin"
PASSWORD = "password123"

def main():
    api_url = sys.argv[1] if len(sys.argv) > 1 else API_URL
    session = requests.Session()

    print(f"Connecting to Sentinel API at {api_url}...")
    try:
        # Try logging in
        res = session.post(f"{api_url}/auth/login", json={
            "email": EMAIL,
            "password": PASSWORD
        })
        
        # If user doesn't exist yet, register
        if res.status_code != 200:
            print("Initial login failed. Registering workspace admin account...")
            reg_res = session.post(f"{api_url}/auth/register", json={
                "username": USERNAME,
                "email": EMAIL,
                "password": PASSWORD
            })
            if reg_res.status_code in (200, 201):
                print("Admin account registered & authenticated!")
            else:
                print(f"Registration failed ({reg_res.status_code}): {reg_res.text}")
                return
        else:
            print("Successfully authenticated with Sentinel Dashboard!")
    except Exception as e:
        print(f"Could not connect to server at {api_url}: {e}")
        return

    prev_net = psutil.net_io_counters()
    prev_time = time.time()

    print("\n[LIVE STREAM ACTIVE] Sampling real device traffic every 2 seconds...")
    print("Press Ctrl+C to stop.\n")

    try:
        while True:
            time.sleep(2.0)
            curr_net = psutil.net_io_counters()
            curr_time = time.time()

            duration = curr_time - prev_time
            src_bytes = max(0, curr_net.bytes_sent - prev_net.bytes_sent)
            dst_bytes = max(0, curr_net.bytes_recv - prev_net.bytes_recv)
            packets = max(0, (curr_net.packets_sent + curr_net.packets_recv) - 
                             (prev_net.packets_sent + prev_net.packets_recv))

            try:
                conns = len(psutil.net_connections(kind='inet'))
            except Exception:
                conns = 8

            payload = {
                "duration": round(duration, 2),
                "srcBytes": src_bytes,
                "dstBytes": dst_bytes,
                "failedLogins": 0,
                "packetCount": packets,
                "connectionRate": round(conns / duration, 2)
            }

            resp = session.post(f"{api_url}/intrusion/analyze", json=payload)
            if resp.status_code == 200:
                data = resp.json()
                score_pct = int(data['anomalyScore'] * 100)
                status = f"[{data['classification'].upper()}]"
                print(f"{status:12} Score: {score_pct:2d}% | Risk: {data['riskLevel']:6} | TX: {src_bytes/1024:6.1f} KB  RX: {dst_bytes/1024:6.1f} KB")
            else:
                print(f"Error {resp.status_code}: {resp.text}")

            prev_net = curr_net
            prev_time = curr_time
    except KeyboardInterrupt:
        print("\nStopping traffic collector. Goodbye!")

if __name__ == "__main__":
    main()
