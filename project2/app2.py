from http.server import BaseHTTPRequestHandler, HTTPServer
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from urllib.parse import urlparse, parse_qs
import base64
import json
import jwt
import datetime
import sqlite3
import unittest
import requests

# Define the host and port for the server
hostName = "localhost"
serverPort = 8080

# Generate private keys
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)
expired_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)

# Serialize private keys
pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
)
expired_pem = expired_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
)

numbers = private_key.private_numbers()

# Helper function to convert an integer to a Base64URL-encoded string
def int_to_base64(value):
    value_hex = format(value, 'x')
    if len(value_hex) % 2 == 1:
        value_hex = '0' + value_hex
    value_bytes = bytes.fromhex(value_hex)
    encoded = base64.urlsafe_b64encode(value_bytes).rstrip(b'=')
    return encoded.decode('utf-8')

# Define the custom HTTP request handler
class MyServer(BaseHTTPRequestHandler):

    # Method to insert a key into the database
    def insert_key_into_database(self, key_data):
        conn = sqlite3.connect('totally_not_my_privateKeys.db')
        cursor = conn.cursor()

        # Calculate expiration timestamp for the key
        expiration_timestamp = int((datetime.datetime.now() + datetime.timedelta(hours=1)).timestamp())

        # Insert the key and expiration timestamp into the database
        cursor.execute("INSERT INTO keys (key, exp) VALUES (?, ?)", (key_data, expiration_timestamp))

        conn.commit()
        conn.close()

    # Define HTTP methods that are not allowed
    def do_PUT(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_PATCH(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_DELETE(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_HEAD(self):
        self.send_response(405)
        self.end_headers()
        return

    # Handle POST requests
    def do_POST(self):
        parsed_path = urlparse(self.path)
        params = parse_qs(parsed_path.query)
        if parsed_path.path == "/auth":
            headers = {
                "kid": "goodKID"
            }
            token_payload = {
                "user": "username",
                "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)
            }
            if 'expired' in params:
                headers["kid"] = "expiredKID"
                token_payload["exp"] = datetime.datetime.utcnow() - datetime.timedelta(hours=1)
            encoded_jwt = jwt.encode(token_payload, pem, algorithm="RS256", headers=headers)
            self.send_response(200)
            self.end_headers()
            self.wfile.write(bytes(encoded_jwt, "utf-8"))

            # Insert key into database after generating JWT
            self.insert_key_into_database(pem)

            return

        self.send_response(405)
        self.end_headers()
        return

    # Handle GET requests
    def do_GET(self):
        if self.path == "/.well-known/jwks.json":
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            keys = {
                "keys": [
                    {
                        "alg": "RS256",
                        "kty": "RSA",
                        "use": "sig",
                        "kid": "goodKID",
                        "n": int_to_base64(numbers.public_numbers.n),
                        "e": int_to_base64(numbers.public_numbers.e),
                    }
                ]
            }
            self.wfile.write(bytes(json.dumps(keys), "utf-8"))
            return

        self.send_response(405)
        self.end_headers()
        return

# Define unit tests for the server
class TestServer(unittest.TestCase):

    def test_auth_endpoint(self):
        response = requests.post('http://localhost:8080/auth')
        self.assertEqual(response.status_code, 200)

    def test_jwks_endpoint(self):
        response = requests.get('http://localhost:8080/.well-known/jwks.json')
        self.assertEqual(response.status_code, 200)
        self.assertTrue('keys' in response.json())

# Entry point of the script
if __name__ == "__main__":
    # Run the unit tests
    unittest.main()

    # Start the server
    webServer = HTTPServer((hostName, serverPort), MyServer)
    try:
        webServer.serve_forever()
    except KeyboardInterrupt:
        pass

    webServer.server_close()
