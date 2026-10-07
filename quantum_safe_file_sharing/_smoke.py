"""Quick HTTP smoke test against a running local server."""
from io import BytesIO

import urllib.request
import http.cookiejar


def post(opener, url, data=None, files=None):
    if files:
        boundary = "----QSFSBoundary"
        chunks = []
        for key, value in (data or {}).items():
            chunks.append(f"--{boundary}\r\nContent-Disposition: form-data; name=\"{key}\"\r\n\r\n{value}\r\n".encode())
        for key, (filename, content) in files.items():
            chunks.append(
                f"--{boundary}\r\nContent-Disposition: form-data; name=\"{key}\"; filename=\"{filename}\"\r\nContent-Type: application/octet-stream\r\n\r\n".encode()
                + content
                + b"\r\n"
            )
        chunks.append(f"--{boundary}--\r\n".encode())
        body = b"".join(chunks)
        req = urllib.request.Request(url, data=body, method="POST")
        req.add_header("Content-Type", f"multipart/form-data; boundary={boundary}")
    else:
        req = urllib.request.Request(url, data=data or b"", method="POST")
    return opener.open(req)


def main():
    jar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
    login_page = opener.open("http://127.0.0.1:5000/login").read()
    assert b"Demo Authentication" in login_page
    opener.open("http://127.0.0.1:5000/login/23MIC0006", data=b"")
    dash = opener.open("http://127.0.0.1:5000/").read()
    assert b"Pranav Anand" in dash
    resp = post(
        opener,
        "http://127.0.0.1:5000/api/send",
        data={"recipient_id": "23MIC0007"},
        files={"file": ("demo.txt", b"smoke test payload")},
    )
    body = resp.read().decode()
    print(body)
    assert '"ok": true' in body or '"ok":true' in body
    print("smoke_ok")


if __name__ == "__main__":
    main()
