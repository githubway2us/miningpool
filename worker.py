import socket
import json
import logging
import time
import struct
from original_script import sha256d

# Worker configuration
SERVER_HOST = "127.0.0.1"  # Replace with pool server IP
SERVER_PORT = 8335
WORKER_ID = "worker1"  # Unique ID for logging

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.FileHandler(f"{WORKER_ID}.log"), logging.StreamHandler()]
)

def mine_block(header_base, target_int, start_nonce, end_nonce, block_height):
    """Mine a nonce range and count hashes."""
    hash_count = 0
    start_time = time.time()
    header_base = bytes.fromhex(header_base)
    
    for nonce in range(start_nonce, end_nonce):
        if nonce % 100000 == 0:
            logging.info(f"Mining nonce {nonce} for height {block_height}...")
        header = header_base + struct.pack("<I", nonce)
        hash_result = sha256d(header)[::-1]
        hash_count += 2
        if int.from_bytes(hash_result, "big") < target_int:
            elapsed = time.time() - start_time
            hash_rate = hash_count / elapsed / 1000000 if elapsed > 0 else 0
            logging.info(f"Found nonce {nonce}! Hash: {hash_result.hex()} Rate: {hash_rate:.2f} MH/s")
            return nonce, hash_result.hex(), hash_count
    elapsed = time.time() - start_time
    hash_rate = hash_count / elapsed / 1000000 if elapsed > 0 else 0
    logging.info(f"No nonce found in {start_nonce}-{end_nonce}. Rate: {hash_rate:.2f} MH/s")
    return None, None, hash_count

def main():
    while True:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
                client.connect((SERVER_HOST, SERVER_PORT))
                logging.info(f"Connected to pool server {SERVER_HOST}:{SERVER_PORT}")
                
                while True:
                    # Receive work
                    data = client.recv(1024).decode().strip()
                    if not data:
                        break
                    if data == "NEW_BLOCK":
                        logging.info("New block found by pool, restarting work")
                        continue
                    
                    work = json.loads(data)
                    header_base = work["header_base"]
                    target_int = int(work["target"], 16)
                    start_nonce = work["start_nonce"]
                    end_nonce = work["end_nonce"]
                    height = work["height"]
                    
                    # Mine the assigned range
                    nonce, block_hash, hash_count = mine_block(
                        header_base, target_int, start_nonce, end_nonce, height
                    )
                    
                    # Send result
                    result = {
                        "worker_id": WORKER_ID,
                        "nonce": nonce,
                        "block_hash": block_hash,
                        "hash_count": hash_count
                    }
                    client.sendall(json.dumps(result).encode() + b"\n")
        
        except Exception as e:
            logging.error(f"Worker error: {e}")
            time.sleep(5)  # Retry after delay

if __name__ == "__main__":
    main()