import socket
import json
import threading
import logging
import time
import struct
from concurrent.futures import ThreadPoolExecutor
from multiprocessing import Lock
from original_script import (
    call_rpc, sha256d, little_endian, to_little_endian_bytes,
    encode_varint, bech32_to_scriptpubkey, get_block_template,
    create_coinbase_tx, build_merkle_root, template_lock,
    current_template, last_template_time, template_timeout
)

# Server configuration
HOST = "0.0.0.0"
PORT = 8335
NONCE_RANGE_SIZE = 1000000  # Nonces per worker assignment
MAX_WORKERS = 50
reward_address = "bc1qmuhxdy836dxertx98s60z24slhpggumrplzcp8"
extranonce_size = 4
extranonce_start = 0

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.FileHandler("pool_server.log"), logging.StreamHandler()]
)

# Worker management
workers = {}
workers_lock = Lock()
current_extranonce = extranonce_start
nonce_cursor = 0

def handle_worker(conn, addr):
    """Handle communication with a single worker."""
    worker_id = f"{addr[0]}:{addr[1]}"
    logging.info(f"Worker {worker_id} connected")
    with workers_lock:
        workers[worker_id] = {"conn": conn, "hash_count": 0, "start_time": time.time()}
    
    try:
        while True:
            # Get block template
            template = get_block_template()
            if not template:
                time.sleep(5)
                continue
            
            height = template["height"]
            version = struct.pack("<I", template["version"])
            prev_block = little_endian(template["previousblockhash"])
            bits = bytes.fromhex(template["bits"])
            target_int = int(template["target"], 16)
            
            global current_extranonce, nonce_cursor
            with template_lock:
                if current_extranonce >= 2**(extranonce_size * 8):
                    current_extranonce = extranonce_start
                    nonce_cursor = 0
                coinbase_tx = create_coinbase_tx(template["coinbasevalue"], height, current_extranonce)
                coinbase_tx_hash = sha256d(coinbase_tx)[::-1].hex()
                tx_hashes = [coinbase_tx_hash] + [tx["txid"] for tx in template["transactions"]]
                merkle_root = bytes.fromhex(build_merkle_root(tx_hashes))
                timestamp = struct.pack("<I", int(time.time()))
                header_base = version + prev_block + merkle_root + timestamp + bits
                
                # Assign nonce range
                start_nonce = nonce_cursor
                end_nonce = min(start_nonce + NONCE_RANGE_SIZE, 2**32)
                nonce_cursor = end_nonce if end_nonce < 2**32 else 0
                if nonce_cursor == 0:
                    current_extranonce += 1
            
            # Send work to worker
            work = {
                "header_base": header_base.hex(),
                "target": template["target"],
                "start_nonce": start_nonce,
                "end_nonce": end_nonce,
                "height": height
            }
            conn.sendall(json.dumps(work).encode() + b"\n")
            
            # Receive result
            data = conn.recv(1024).decode().strip()
            if not data:
                break
            result = json.loads(data)
            
            with workers_lock:
                workers[worker_id]["hash_count"] += result["hash_count"]
            
            if result["nonce"] is not None:
                logging.info(f"Worker {worker_id} found nonce {result['nonce']} for height {height}")
                # Construct and submit block
                tx_count = encode_varint(len(tx_hashes))
                block = (
                    header_base +
                    struct.pack("<I", result["nonce"]) +
                    tx_count +
                    coinbase_tx +
                    b"".join([bytes.fromhex(tx["data"]) for tx in template["transactions"]])
                )
                try:
                    submit_result = call_rpc("submitblock", [block.hex()])
                    if submit_result is None:
                        logging.info(f"Block accepted for height {height}!")
                        with workers_lock:
                            for w in workers.values():
                                w["conn"].sendall(b"NEW_BLOCK\n")
                        nonce_cursor = 0
                        current_extranonce = extranonce_start
                    else:
                        logging.warning(f"Block submission failed: {submit_result}")
                except Exception as e:
                    logging.error(f"Block submission error: {e}")
    
    except Exception as e:
        logging.error(f"Worker {worker_id} error: {e}")
    finally:
        conn.close()
        with workers_lock:
            del workers[worker_id]
        logging.info(f"Worker {worker_id} disconnected")

def monitor_workers():
    """Log worker stats periodically."""
    while True:
        time.sleep(60)
        with workers_lock:
            if workers:
                logging.info(f"Active workers: {len(workers)}")
                for wid, w in workers.items():
                    elapsed = time.time() - w["start_time"]
                    hash_rate = w["hash_count"] / elapsed / 1000000 if elapsed > 0 else 0
                    logging.info(f"Worker {wid}: {hash_rate:.2f} MH/s")
            else:
                logging.info("No active workers")

def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen(MAX_WORKERS)
    logging.info(f"Pool server started on {HOST}:{PORT}")
    
    threading.Thread(target=monitor_workers, daemon=True).start()
    
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        while True:
            conn, addr = server.accept()
            executor.submit(handle_worker, conn, addr)

if __name__ == "__main__":
    main()