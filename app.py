import sys
from flask import Flask, render_template, request

app = Flask(__name__)

app.config["TEMPLATES_AUTO_RELOAD"] = True

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        # print(username)
        # print(password)
        # request.files.get("filename").save("captured_file")

        if not username or not password:
            return render_template("error.html")

        return render_template("success.html")

    # request.method == "GET"
    return render_template("index.html")

if __name__ == "__main__":
    if len(sys.argv) == 2 and "encrypt" in sys.argv[1]:
        app.run(host="127.0.0.1", port=5000, ssl_context="adhoc")
    else:
        app.run(host="127.0.0.1", port=5000)
