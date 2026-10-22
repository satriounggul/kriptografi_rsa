"""
Local HTTP Server for Multi-Prime RSA Application.
Simplified version: Key Generation and Encryption/Decryption only.
Zero external dependencies (uses standard library http.server).
"""

import http.server
import json
import os
import sys
import traceback
import urllib.parse
from typing import Dict, Any

# Ensure project root is in sys.path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from core.keygen import generate_keys
from core.codec import text_to_blocks, blocks_to_text
from core.rsa import encrypt, decrypt_standard, decrypt_crt_garner, decrypt_crt_gauss

STATIC_DIR = os.path.join(PROJECT_ROOT, "static")


def serialize_bigints(obj: Any) -> Any:
    """Recursively converts all integers to strings for consistent JSON serialization."""
    if isinstance(obj, int):
        return str(obj)
    elif isinstance(obj, dict):
        return {k: serialize_bigints(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [serialize_bigints(item) for item in obj]
    elif isinstance(obj, tuple):
        return [serialize_bigints(item) for item in obj]
    return obj


class RSAHandler(http.server.BaseHTTPRequestHandler):

    server_version = "MultiPrimeRSA/1.0"

    def _set_headers(self, status: int = 200, content_type: str = "application/json") -> None:
        self.send_response(status)
        self.send_header("Content-Type", f"{content_type}; charset=utf-8")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
        self.end_headers()

    def do_OPTIONS(self) -> None:
        self._set_headers(200)

    def _send_json_error(self, message: str, status: int = 400) -> None:
        self._set_headers(status, "application/json")
        response = {"error": message, "status": status}
        self.wfile.write(json.dumps(response).encode("utf-8"))

    def _send_json_response(self, data: Any, status: int = 200) -> None:
        self._set_headers(status, "application/json")
        serialized = serialize_bigints(data)
        self.wfile.write(json.dumps(serialized).encode("utf-8"))

    def _read_json_body(self) -> Dict[str, Any]:
        content_length = int(self.headers.get("Content-Length", 0))
        if content_length <= 0:
            return {}
        raw_body = self.rfile.read(content_length).decode("utf-8")
        try:
            return json.loads(raw_body)
        except json.JSONDecodeError as e:
            raise ValueError(f"Format JSON tidak valid: {str(e)}")

    def do_GET(self) -> None:
        parsed_url = urllib.parse.urlparse(self.path)
        path = parsed_url.path

        # Serve static frontend files
        if path == "/" or path == "/index.html":
            file_path = os.path.join(STATIC_DIR, "index.html")
            content_type = "text/html"
        elif path == "/style.css":
            file_path = os.path.join(STATIC_DIR, "style.css")
            content_type = "text/css"
        elif path == "/app.js":
            file_path = os.path.join(STATIC_DIR, "app.js")
            content_type = "application/javascript"
        else:
            safe_rel = os.path.normpath(path.lstrip("/\\"))
            file_path = os.path.join(STATIC_DIR, safe_rel)
            if not file_path.startswith(STATIC_DIR) or not os.path.exists(file_path):
                self._send_json_error("Halaman tidak ditemukan", 404)
                return
            if file_path.endswith(".css"):
                content_type = "text/css"
            elif file_path.endswith(".js"):
                content_type = "application/javascript"
            elif file_path.endswith(".html"):
                content_type = "text/html"
            else:
                content_type = "application/octet-stream"

        if os.path.exists(file_path) and os.path.isfile(file_path):
            with open(file_path, "rb") as f:
                content = f.read()
            self._set_headers(200, content_type)
            self.wfile.write(content)
        else:
            self._send_json_error("Berkas tidak ditemukan", 404)

    def do_POST(self) -> None:
        parsed_url = urllib.parse.urlparse(self.path)
        path = parsed_url.path

        try:
            body = self._read_json_body()
        except ValueError as e:
            self._send_json_error(str(e), 400)
            return

        try:
            if path == "/keygen":
                self._handle_keygen(body)
            elif path == "/encrypt":
                self._handle_encrypt(body)
            elif path == "/decrypt":
                self._handle_decrypt(body)
            else:
                self._send_json_error(f"Endpoint tidak dikenal: {path}", 404)
        except Exception as e:
            traceback.print_exc()
            self._send_json_error(f"Kesalahan internal pemrosesan: {str(e)}", 500)

    # ------------------ Handler Methods ------------------

    def _handle_keygen(self, body: Dict[str, Any]) -> None:
        """Pembangkitan Kunci Multi-Prime RSA."""
        try:
            bits = int(body.get("bits", 512))
            k = int(body.get("k", 3))
        except (ValueError, TypeError):
            self._send_json_error("Parameter 'bits' dan 'k' harus berupa bilangan bulat.")
            return

        if k < 2 or k > 8:
            self._send_json_error("Jumlah prima 'k' harus antara 2 dan 8.")
            return
        if bits < 16 or bits > 4096:
            self._send_json_error("Ukuran 'bits' harus antara 16 dan 4096.")
            return
        if bits // k < 4:
            self._send_json_error(f"Ukuran bit per prima ({bits // k}) terlalu kecil. Tambah bit atau kurangi k.")
            return

        keys = generate_keys(bits=bits, k=k)

        response = {
            "public_key": keys["public_key"],
            "private_key": keys["private_key"]
        }
        self._send_json_response(response)

    def _handle_encrypt(self, body: Dict[str, Any]) -> None:
        """Enkripsi Pesan."""
        n_str = body.get("n")
        e_str = body.get("e")
        message = body.get("message")
        is_text = bool(body.get("is_text", False))

        if not n_str or not e_str or message is None:
            self._send_json_error("Data tidak lengkap: 'n', 'e', dan 'message' wajib diisi.")
            return

        try:
            n = int(n_str)
            e = int(e_str)
        except ValueError:
            self._send_json_error("Kunci 'n' dan 'e' harus berupa angka yang valid.")
            return

        if is_text:
            text_str = str(message)
            try:
                blocks = text_to_blocks(text_str, n)
            except ValueError as ve:
                self._send_json_error(f"Gagal memecah blok teks: {str(ve)}")
                return

            cipher_blocks = [encrypt(b, e, n) for b in blocks]
            self._send_json_response({
                "mode": "text",
                "blocks_count": len(blocks),
                "plaintext_blocks": blocks,
                "ciphertext_blocks": cipher_blocks,
                "ciphertext_hex": " ".join(hex(c)[2:] for c in cipher_blocks)
            })
        else:
            try:
                m = int(str(message).strip())
            except ValueError:
                self._send_json_error("Pesan harus berupa bilangan bulat jika mode angka dipilih.")
                return

            if m < 0 or m >= n:
                self._send_json_error(f"Pesan m harus memenuhi 0 <= m < n. (Ukuran n saat ini: {n.bit_length()} bit)")
                return

            c = encrypt(m, e, n)
            self._send_json_response({
                "mode": "number",
                "plaintext": m,
                "ciphertext": c
            })

    def _handle_decrypt(self, body: Dict[str, Any]) -> None:
        """Dekripsi Pesan."""
        key_data = body.get("key_data")
        method = body.get("method", "crt_garner").lower()
        is_text = bool(body.get("is_text", False))
        ciphertext = body.get("ciphertext")

        if not key_data or ciphertext is None:
            self._send_json_error("Data tidak lengkap: 'key_data' dan 'ciphertext' wajib diisi.")
            return

        try:
            n = int(key_data["n"])
            k = int(key_data.get("k", 2))
        except (KeyError, ValueError):
            self._send_json_error("Data kunci tidak valid: n dan k diperlukan.")
            return

        # Persiapan data kunci privat
        try:
            priv = {
                "n": n,
                "k": k,
                "primes": [int(p) for p in key_data.get("primes", [])],
                "d_primes": [int(dp) for dp in key_data.get("d_primes", [])],
                "t_coeffs": [int(t) for t in key_data.get("t_coeffs", [])]
            }
            if "d" in key_data and key_data["d"]:
                priv["d"] = int(key_data["d"])
        except ValueError:
            self._send_json_error("Komponen kunci privat tidak valid.")
            return

        # Pilihan metode dekripsi
        if method == "standard":
            if "d" not in priv:
                self._send_json_error("Dekripsi standar memerlukan eksponen privat 'd'.")
                return
            decrypt_fn = lambda c_val: decrypt_standard(c_val, priv["d"], n)
        elif method == "crt_garner":
            if len(priv["primes"]) != k or len(priv["d_primes"]) != k or len(priv["t_coeffs"]) != k - 1:
                self._send_json_error(f"Metode CRT Garner memerlukan {k} prima, {k} d_i, dan {k-1} t_i.")
                return
            decrypt_fn = lambda c_val: decrypt_crt_garner(c_val, priv)
        elif method == "crt_gauss":
            if len(priv["primes"]) != k or len(priv["d_primes"]) != k:
                self._send_json_error(f"Metode CRT Gauss memerlukan {k} prima dan {k} d_i.")
                return
            decrypt_fn = lambda c_val: decrypt_crt_gauss(c_val, priv)
        else:
            self._send_json_error(f"Metode dekripsi tidak valid: '{method}'.")
            return

        if is_text:
            if isinstance(ciphertext, list):
                c_blocks = [int(c) for c in ciphertext]
            elif isinstance(ciphertext, str):
                parts = ciphertext.replace(",", " ").split()
                c_blocks = [int(c, 16) if c.startswith("0x") else int(c) for c in parts]
            else:
                self._send_json_error("Format ciphertext teks harus berupa list atau angka yang dipisahkan spasi.")
                return

            decrypted_blocks = []
            steps_first_block = None
            total_time = 0.0

            for idx, c_val in enumerate(c_blocks):
                m_val, steps = decrypt_fn(c_val)
                decrypted_blocks.append(m_val)
                total_time += steps.get("execution_time_s", 0.0)
                if idx == 0:
                    steps_first_block = steps

            recovered_text = blocks_to_text(decrypted_blocks, n)

            self._send_json_response({
                "mode": "text",
                "method": method,
                "recovered_text": recovered_text,
                "decrypted_blocks": decrypted_blocks,
                "total_execution_time_s": total_time,
                "sample_block_intermediate_steps": steps_first_block
            })
        else:
            try:
                c_val = int(str(ciphertext).strip())
            except ValueError:
                self._send_json_error("Ciphertext harus berupa angka yang valid.")
                return

            m_val, steps = decrypt_fn(c_val)

            self._send_json_response({
                "mode": "number",
                "method": method,
                "plaintext": m_val,
                "intermediate_steps": steps,
                "execution_time_s": steps.get("execution_time_s", 0.0),
                "operation_counts": steps.get("operation_counts", {})
            })


def run_server(host: str = "127.0.0.1", port: int = 8000) -> None:
    server_address = (host, port)
    httpd = http.server.HTTPServer(server_address, RSAHandler)
    print(f"=== Multi-Prime RSA Server berjalan di http://{host}:{port} ===")
    print("Tekan Ctrl+C untuk menghentikan server.")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nMenghentikan server...")
        httpd.server_close()


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Multi-Prime RSA Web Server")
    parser.add_argument("--host", default="127.0.0.1", help="Host (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8000, help="Port (default: 8000)")
    args = parser.parse_args()

    if args.host not in ("127.0.0.1", "localhost"):
        args.host = "127.0.0.1"

    run_server(host=args.host, port=args.port)
