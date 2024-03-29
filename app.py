import sys
from time import time
from flask import Flask, make_response, render_template, request
import jwt

app = Flask(__name__)

app.config["TEMPLATES_AUTO_RELOAD"] = True

logins = {}


def create_cookie(username: str, password: str) -> str:
    payload = {}
    current_time = int(time())
    payload["exp"] = str(current_time + 86400)
    payload["iat"] = str(current_time)
    payload["sub"] = username
    return jwt.encode(payload, password, "HS256")


@app.route("/", methods=["GET", "POST"])
def index():
    # If you see a browser message asking you to reconfirm submission, this means
    # you're resubmitting a POST request
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        # print(username)
        # print(password)
        # request.files.get("filename").save("captured_file")

        if username not in logins:
            logins[username] = password
            resp = make_response(render_template("success.html", user=username, existing=""))
            resp.set_cookie("auth_token", create_cookie(username, password), max_age=86400, httponly=True, samesite="Lax")
            return resp
        elif username in logins and password == logins[username]:
            resp = make_response(render_template("success.html", user=username, existing=" back"))
            resp.set_cookie("auth_token", create_cookie(username, password), max_age=86400, httponly=True, samesite="Lax")
            return resp
        else:
            return make_response(render_template("error.html"), 403)

    # request.method == "GET"
    jwt_cookie = request.cookies.get("auth_token")
    if jwt_cookie is not None:
        decoded_token = jwt.decode(jwt_cookie, options={"verify_signature": False})
        iat = int(decoded_token["iat"])
        exp = int(decoded_token["exp"])
        current_time = int(time())
        if iat < current_time and exp > current_time:
            sub = decoded_token["sub"]
            if sub in logins:
                key = logins[sub]
                jwt.decode(jwt_cookie, key, ["HS256"])
                return render_template("success.html", user=sub, existing=" back")
    return render_template("index.html")


@app.route("/logout", methods=["GET"])
def logout():
    resp = make_response(render_template("index.html"))
    resp.set_cookie("auth_token", max_age=0)
    return resp


if __name__ == "__main__":
    if len(sys.argv) == 2 and "encrypt" in sys.argv[1]:
        app.run(host="127.0.0.1", port=5000, ssl_context="adhoc")
    else:
        app.run(host="127.0.0.1", port=5000)
