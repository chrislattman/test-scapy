from flask import Flask, render_template, request

app = Flask(__name__)

app.config["TEMPLATES_AUTO_RELOAD"] = True

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        if not username or not password:
            return render_template("error.html")

        return render_template("success.html")

    # request.method == "GET"
    return render_template("index.html")

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000)
