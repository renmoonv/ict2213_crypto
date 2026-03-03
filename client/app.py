from flask import Flask, render_template, request, redirect, url_for, session, flash
from auth import register as do_register, login as do_login, logout as do_logout, get_private_key_bytes

app = Flask(__name__)
app.secret_key = "dev-only-change-me"  # for demo; change before submission if required


@app.get("/")
def landingpage():
    logged_in = session.get("logged_in", False)
    username = session.get("username")
    has_privkey = get_private_key_bytes() is not None
    return render_template("landingpage.html", logged_in=logged_in, username=username, has_privkey=has_privkey)

# register
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if not username or not password:
            flash("Username and password required.", "error")
            return redirect(url_for("register"))

        ok = do_register(username, password)
        if ok:
            flash("Registered successfully. You can login now.", "success")
            return redirect(url_for("login"))
        else:
            # Even if server is down, your do_register may still save keystore locally (depending on your logic)
            flash("Register completed locally, but server registration may have failed (server/TLS not running).", "warning")
            return redirect(url_for("login"))

    return render_template("register.html")

# login
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        if do_login(username, password):
            # mark session as logged in so protected pages work
            session["logged_in"] = True
            session["username"] = username
            flash("Login successful.", "success")
            return redirect(url_for("home"))
        else:
            flash("Login failed.", "error")

    return render_template(
        "login.html",
        logged_in=get_private_key_bytes() is not None
    )

# Logout
@app.post("/logout")
def logout():
    do_logout()
    session.clear()
    flash("Logged out. Private key cleared from memory.", "success")
    return redirect(url_for("landingpage"))

# Home page
@app.get("/home")
def home():
    if not session.get("logged_in"):
        flash("Please login first.", "error")
        return redirect(url_for("login"))

    username = session.get("username")
    has_privkey = get_private_key_bytes() is not None

    return render_template(
        "home.html",
        username=username,
        has_privkey=has_privkey
    )




if __name__ == "__main__":
    # UI server (this is your client UI). Keep it HTTP locally.
    # TLS for your project is for the *API server / reverse proxy*, not necessarily this UI.
    app.run(host="127.0.0.1", port=5001, debug=True)