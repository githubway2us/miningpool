# original_script.py
import hashlib
import requests
import struct
import time
import logging
from bech32 import decode, convertbits
from threading import Lock

# Configuration
rpc_user = "user"
rpc_password = "password"
rpc_url = "http://127.0.0.1:8332"
reward_address = "bc1qmuhxdy836dxertx98s60z24slhpggumrplzcp8"  # เพิ่มตัวแปรนี้
template_timeout = 300
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.FileHandler("mining.log"), logging.StreamHandler()]
)

# Global variables
template_lock = Lock()
current_template = None
last_template_time = 0

# RPC and helper functions
def call_rpc(method, params=None):
    """เรียกใช้ JSON-RPC เพื่อสื่อสารกับ Bitcoin node"""
    if params is None:
        params = []
    headers = {"content-type": "application/json"}
    payload = {
        "jsonrpc": "2.0",
        "id": "python",
        "method": method,
        "params": params
    }
    try:
        response = requests.post(
            rpc_url, json=payload, headers=headers,
            auth=(rpc_user, rpc_password), timeout=5
        )
        response.raise_for_status()
        result = response.json()
        if "error" in result and result["error"] is not None:
            raise Exception(f"ข้อผิดพลาด RPC: {result['error']}")
        return result["result"]
    except requests.RequestException as e:
        logging.error(f"การเรียก RPC ล้มเหลว: {e}")
        raise

def sha256d(b):
    """คำนวณ double SHA-256 hash"""
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()

def little_endian(hexstr):
    """แปลง hex string เป็น bytes ในลำดับ little-endian"""
    return bytes.fromhex(hexstr)[::-1]

def to_little_endian_bytes(n, length):
    """แปลงตัวเลขเป็น bytes ในลำดับ little-endian"""
    return n.to_bytes(length, byteorder="little")

def encode_varint(i):
    """เข้ารหัสตัวเลขเป็น varint สำหรับ Bitcoin protocol"""
    if i < 0xfd:
        return struct.pack("<B", i)
    elif i <= 0xffff:
        return b"\xfd" + struct.pack("<H", i)
    elif i <= 0xffffffff:
        return b"\xfe" + struct.pack("<I", i)
    else:
        return b"\xff" + struct.pack("<Q", i)

def bech32_to_scriptpubkey(address, network="main"):
    """แปลงที่อยู่ Bech32 เป็น scriptPubKey"""
    try:
        validate_result = call_rpc("validateaddress", [address])
        if not validate_result["isvalid"]:
            raise ValueError(f"ที่อยู่ {address} ไม่ถูกต้อง")
        if validate_result.get("iswitness") and "scriptPubKey" in validate_result:
            logging.info(f"ใช้ scriptPubKey จาก validateaddress สำหรับ {address}")
            return validate_result["scriptPubKey"]
    except Exception as e:
        logging.warning(f"การตรวจสอบที่อยู่ผ่าน RPC ล้มเหลว: {e}")
    expected_hrp = {"main": "bc", "test": "tb", "regtest": "bcrt"}.get(network, "bc")
    try:
        hrp, data = decode(expected_hrp, address)
        if hrp != expected_hrp:
            raise ValueError(f"HRP ไม่ถูกต้อง: คาดว่า {expected_hrp}, ได้ {hrp}")
        converted = convertbits(data[1:], 5, 8, False)
        if not converted:
            raise ValueError("แปลงบิต Bech32 ไม่สำเร็จ")
        witness_program = bytes(converted).hex()
        return f"0014{witness_program}"
    except Exception as e:
        logging.error(f"การถอดรหัส Bech32 ล้มเหลว: {e}")
        raise ValueError(f"ที่อยู่ Bech32 ไม่ถูกต้อง: {e}")

def get_block_template():
    """ดึง block template จาก Bitcoin node"""
    global current_template, last_template_time
    with template_lock:
        if current_template and time.time() - last_template_time < template_timeout:
            return current_template
        try:
            logging.info("กำลังดึงเทมเพลตบล็อกใหม่...")
            template = call_rpc("getblocktemplate", [{"rules": ["segwit"]}])
            current_template = template
            last_template_time = time.time()
            logging.info(f"ดึงเทมเพลตสำเร็จ: ความสูง {template['height']}")
            return template
        except Exception as e:
            logging.error(f"ไม่สามารถดึงเทมเพลตบล็อก: {e}")
            return None

def create_coinbase_tx(coinbase_value, height, extranonce):
    """สร้าง coinbase transaction สำหรับบล็อก"""
    logging.info(f"สร้าง coinbase: ความสูง {height}, มูลค่า {coinbase_value}")
    height_bytes = encode_varint(height)
    extranonce_bytes = extranonce.to_bytes(4, byteorder="big")  # extranonce_size = 4 จากโค้ดเดิม
    script_sig = height_bytes + extranonce_bytes + b"\x00"
    coinbase_input = (
        b"\x00\x00\x00\x00" +
        b"\x01" +
        b"\x00" * 32 + b"\xff\xff\xff\xff" +
        bytes([len(script_sig)]) + script_sig +
        b"\xff\xff\xff\xff"
    )
    network = call_rpc("getblockchaininfo")["chain"]
    pk_script = bytes.fromhex(bech32_to_scriptpubkey(reward_address, network))
    coinbase_output = (
        b"\x01" +
        to_little_endian_bytes(coinbase_value, 8) +
        bytes([len(pk_script)]) + pk_script
    )
    locktime = b"\x00\x00\x00\x00"
    return coinbase_input + coinbase_output + locktime

def build_merkle_root(tx_hashes):
    """คำนวณ Merkle root จากรายการ transaction hashes"""
    try:
        hashes = [little_endian(tx) for tx in tx_hashes]
        while len(hashes) > 1:
            if len(hashes) % 2 == 1:
                hashes.append(hashes[-1])
            hashes = [sha256d(hashes[i] + hashes[i + 1]) for i in range(0, len(hashes), 2)]
        return hashes[0][::-1].hex()
    except ValueError as e:
        logging.error(f"แฮชธุรกรรมไม่ถูกต้อง: {e}")
        raise