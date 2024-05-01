import os
import sys
from time import time

import bcrypt
# from werkzeug.datastructures.auth import WWWAuthenticate
import jwt
from flask import Flask, make_response, render_template, request

app = Flask(__name__)

app.config["TEMPLATES_AUTO_RELOAD"] = True

logins = {}

var = os.getenv("FILE_UPLOAD")
if var and var == "1":
    file_upload = True
else:
    file_upload = False


def create_cookie(username: str, key: bytes) -> str:
    payload = {}
    current_time = int(time())
    payload["exp"] = str(current_time + 86400)
    payload["iat"] = str(current_time)
    payload["sub"] = username
    return jwt.encode(payload, key, "HS256")


@app.route("/", methods=["GET", "POST"])
def index():
    # If you see a browser message asking you to confirm form resubmission, this
    # means you're resending a POST request
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        # request.files.get("filename").save("captured_file")

        if username is not None and password is not None:
            if username not in logins:
                salt = bcrypt.gensalt()
                hashed_password = bcrypt.hashpw(password.encode(), salt)
                key = salt + hashed_password
                logins[username] = key
                resp = make_response(
                    render_template("success.html", user=username, existing="")
                )
                # https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie
                resp.set_cookie(
                    "auth_token",
                    create_cookie(username, key),
                    max_age=86400,
                    httponly=True,
                    samesite="Lax",
                )
                return resp
            else:
                key = logins[username]
                salt = key[:29]
                hashed_password = key[29:]
                hashed_provided_password = bcrypt.hashpw(password.encode(), salt)
                if hashed_password == hashed_provided_password:
                    resp = make_response(
                        render_template("success.html", user=username, existing=" back")
                    )
                    resp.set_cookie(
                        "auth_token",
                        create_cookie(username, key),
                        max_age=86400,
                        httponly=True,
                        samesite="Lax",
                    )
                    return resp
        return make_response(render_template("error.html"), 403)

    # request.method == "GET"

    # if request.authorization and request.authorization.username == "user" and request.authorization.password == "pass":
    #     pass
    # else:
    #     resp = make_response(render_template("error.html"), 401)
    #     # https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/WWW-Authenticate
    #     resp.www_authenticate = WWWAuthenticate("basic", {"realm": "Authentication Required"})
    #     return resp

    token = request.cookies.get("auth_token")
    try:
        if token is not None:
            decoded_token = jwt.decode(token, options={"verify_signature": False})
            iat = int(decoded_token["iat"])
            exp = int(decoded_token["exp"])
            current_time = int(time())
            if current_time > iat and current_time < exp:
                sub = decoded_token["sub"]
                if sub in logins:
                    key = logins[sub]
                    jwt.decode(token, key, ["HS256"])
                    return render_template("success.html", user=sub, existing=" back")
    except:
        return render_template("index.html", file_upload=file_upload)
    # The line below gets called if no exceptions are thrown but the token is invalid or not present
    return render_template("index.html", file_upload=file_upload)


@app.route("/logout", methods=["GET"])
def logout():
    resp = make_response(render_template("index.html", file_upload=file_upload))
    resp.delete_cookie("auth_token") # same as resp.set_cookie("auth_token", max_age=0)
    return resp


if __name__ == "__main__":
    if len(sys.argv) == 2 and "encrypt" in sys.argv[1]:
        app.run(host="127.0.0.1", port=5000, ssl_context="adhoc")
    else:
        app.run(host="127.0.0.1", port=5000)
