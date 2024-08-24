#!/usr/bin/env python3
from mysql.connector import connect
from mysql.connector import errors
import http.server, socketserver, json, re, ssl

connection = connect(user="wpyh", password="wpyh", host="localhost", database="wpyh")
connection.autocommit = True

cursor = connection.cursor()


def is_ip_address(address):
    ip_pattern = re.compile(
        r"^(\d{1,3}\.){3}\d{1,3}$|"
        r"^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|"
        r"^([0-9a-fA-F]{1,4}:){1,7}:$|"
        r"^:(:[0-9a-fA-F]{1,4}){1,7}$|"
        r"^([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}$|"
        r"^([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}$|"
        r"^([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}$|"
        r"^([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}$|"
        r"^([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}$|"
        r"^[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})$|"
        r"^:((:[0-9a-fA-F]{1,4}){1,7}|:)$|"
        r"^fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}$|"
        r"::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]|)[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]|)[0-9])$|"
        r"([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]|)[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]|)[0-9])$"
    )
    if ip_pattern.match(address):
        if "." in address:
            return all(0 <= int(octet) <= 255 for octet in address.split("."))
        return True
    return False


def is_hostname(hostname):
    pattern = re.compile(
        r"(?i)^(?:([a-z0-9-]+|\*)\.)?([a-z0-9-]{1,61})\.([a-z0-9]{2,7})$"
    )
    return bool(re.match(pattern, hostname))


class CustomHTTPRequestHandler(http.server.BaseHTTPRequestHandler):
    def send_answer(self, code, content):
        self.send_response(code)
        self.send_header("Content-type", "text/plain")
        self.end_headers()
        self.wfile.write(content.encode())

    def do_GET(self):
        domain = self.path.removeprefix("/")
        cursor.execute("SELECT * FROM domains WHERE domain = %s LIMIT 1", (domain,))
        result = cursor.fetchone()
        if result:
            self.send_answer(200, str(result[1]))
        else:
            self.send_answer(404, "404 No domain found")

    def do_POST(self):
        content_length = int(self.headers["Content-Length"])
        post_data = self.rfile.read(content_length).decode("utf-8")
        try:
            json_data = json.loads(post_data)
        except json.JSONDecodeError:
            self.send_answer(400, "400 Malformed JSON")
            return

        if (
            "domain" not in json_data
            or "ip" not in json_data
            or "secret_key" not in json_data
        ):
            self.send_answer(400, "400 Missing keys")
            return

        if not is_ip_address(json_data["ip"]):
            self.send_answer(400, "400 Malformed IP")
            return

        if not is_hostname(json_data["domain"]):
            self.send_answer(400, "400 Malformed Domain")
            return

        try:
            cursor.execute(
                "INSERT INTO domains (domain, ip, secret_key) VALUES (%s, %s, %s)",
                (json_data["domain"], json_data["ip"], json_data["secret_key"]),
            )
        except errors.IntegrityError as e:
            match = re.search(r"entry\s+'([^']+)'", str(e))
            if match:
                self.send_answer(409, f"409 Conflict {match.group(1)}")
            else:
                self.send_answer(409, "409 Conflict")
            return

        self.send_answer(200, "200 Inserted")

    def do_PUT(self):
        content_length = int(self.headers["Content-Length"])
        post_data = self.rfile.read(content_length).decode("utf-8")
        try:
            json_data = json.loads(post_data)
        except json.JSONDecodeError:
            self.send_answer(400, "400 Malformed JSON")
            return

        if "domain" not in json_data or "secret_key" not in json_data:
            self.send_answer(400, "400 Missing keys")
            return

        if not is_hostname(json_data["domain"]):
            self.send_answer(400, "400 Malformed Domain")
            return

        cursor.execute(
            "SELECT * FROM domains WHERE domain = %s AND secret_key = %s",
            (json_data["domain"], json_data["secret_key"]),
        )
        if not cursor.fetchone():
            self.send_answer(404, "404 No Entry Found")
            return

        cursor.execute(
            "UPDATE domains SET ip = %s WHERE domain = %s AND secret_key = %s",
            (json_data["ip"], json_data["domain"], json_data["secret_key"]),
        )
        self.send_answer(200, "200 Updated")

    def do_DELETE(self):
        content_length = int(self.headers["Content-Length"])
        post_data = self.rfile.read(content_length).decode("utf-8")
        try:
            json_data = json.loads(post_data)
        except json.JSONDecodeError:
            self.send_answer(400, "400 Malformed JSON")
            return

        if "domain" not in json_data or "secret_key" not in json_data:
            self.send_answer(400, "400 Missing keys")
            return

        cursor.execute(
            "SELECT * FROM domains WHERE domain = %s AND secret_key = %s",
            (json_data["domain"], json_data["secret_key"]),
        )
        if not cursor.fetchone():
            self.send_answer(404, "404 No Entry Found")
            return

        cursor.execute(
            "DELETE FROM domains WHERE domain = %s AND secret_key = %s",
            (json_data["domain"], json_data["secret_key"]),
        )
        self.send_answer(200, "200 Removed")


ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ssl_context.load_cert_chain(
    "/etc/letsencrypt/live/gnuhobbyhub.de/fullchain.pem",
    "/etc/letsencrypt/live/gnuhobbyhub.de/privkey.pem",
)

server = socketserver.TCPServer(("0.0.0.0", 8952), CustomHTTPRequestHandler)
print("Serving the customers")
server.socket = ssl_context.wrap_socket(server.socket, server_side=True)
server.serve_forever()
