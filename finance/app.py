import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    user_id = session["user_id"]

    stocks = db.execute("SELECT symbol, SUM(shares) AS total_shares FROM transactions WHERE user_id = ? GROUP BY symbol", user_id)

    cash_rows = db.execute("SELECT cash FROM users WHERE id = ?", user_id)
    cash_owned = cash_rows[0]["cash"]

    name_rows = db.execute("SELECT username FROM users WHERE id = ?", user_id)
    username = name_rows[0]["username"]

    portfolio = []
    total_stock_value = 0

    for stock in stocks:
        symbol = stock["symbol"]
        shares = stock["total_shares"]

        # if sold shares don't show 0
        if shares <= 0:
            continue

        quote = lookup(symbol)
        current_share_price = quote["price"]
        total_shares_value = shares * current_share_price

        portfolio.append({
            "symbol": symbol,
            "company_name": quote["name"],
            "total_shares_owned": shares,
            "current_share_price": current_share_price,
            "total_shares_value": total_shares_value,
        })

        total_stock_value += total_shares_value

    grand_total = total_stock_value + cash_owned

    return render_template("index.html", username=username, portfolio=portfolio, grand_total=grand_total, cash_owned=cash_owned)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    # if visitied via GET
    if request.method == "GET":
        return render_template("buy.html")

    if request.method == "POST":
        symbol = request.form.get("symbol")
        shares_str = request.form.get("shares")
        # validating user inputs
        if not symbol:
            return apology("must provide a symbol", 400)
        stock = lookup(symbol)

        if stock is None:
            return apology("invalid symbol", 400)

        if not shares_str:
            return apology("must provide shares number", 400)

        try:
            shares_count = int(shares_str)
            if shares_count <= 0:
                return apology("shares must be positive", 400)
        except ValueError:
            return apology("shares must be a number", 400)

        user_id = session["user_id"]
        rows = db.execute("SELECT cash FROM users WHERE id = ?", user_id)
        user_current_cash = rows[0]["cash"]
        share_price = stock["price"]
        total_price = shares_count * share_price
        # cash validation
        if user_current_cash >= total_price:
            db.execute("UPDATE users SET cash = ? WHERE id = ?", user_current_cash - total_price, user_id)
            db.execute("INSERT INTO transactions (user_id, symbol, shares, price) VALUES (?, ?, ?, ?)", user_id, symbol, shares_count, share_price)
            return redirect("/")
        else:
            return apology("Not enough cash", 400)


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    transactions = db.execute("SELECT symbol, shares, price, timestamp FROM transactions WHERE user_id = ? ORDER BY timestamp DESC", session["user_id"])
    return render_template("history.html", transactions=transactions)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute(
            "SELECT * FROM users WHERE username = ?", request.form.get("username")
        )

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(
            rows[0]["hash"], request.form.get("password")
        ):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    # if visitied via GET
    if request.method == "GET":
        return render_template("quote.html")

    if request.method == "POST":
        symbol = request.form.get("symbol")
        if not symbol:
            return apology("must provide symbol", 400)
        result = lookup(symbol)
        if result is None:
            return apology("invalid symbol", 400)
        return render_template("quoted.html", result=result)


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
        # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)
        elif not request.form.get("confirmation"):
            return apology("must confirm password", 403)
        # Ensure password and confirmation are same
        elif request.form.get("password") != request.form.get("confirmation"):
            return apology("Passwords do not match", 403)

        # adding new user to the database
        try:
            username = request.form.get("username")
            password = request.form.get("password")
            db.execute("INSERT INTO users (username, hash) VALUES (?, ?)", username, generate_password_hash(password))
        except:
            return apology("username already taken", 403)
        # returning user back to logging in if successfully registered
        return redirect("/login")
     # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("register.html")

@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    if request.method == "GET":
        stocks = db.execute("SELECT symbol FROM transactions WHERE user_id = ? GROUP BY symbol HAVING SUM(shares) > 0", session["user_id"])
        return render_template("sell.html", stocks=stocks)

    if request.method == "POST":
        symbol = request.form.get("symbol")
        shares_str = request.form.get("shares")
        # validating user inputs
        if not symbol:
            return apology("must provide a symbol", 400)
        stock = lookup(symbol)

        if stock is None:
            return apology("invalid symbol", 400)

        if not shares_str:
            return apology("must provide shares number", 400)

        try:
            shares_count = int(shares_str)
            if shares_count <= 0:
                return apology("shares must be positive", 400)
        except ValueError:
            return apology("shares must be a number", 400)

        shares_owned = db.execute("SELECT SUM(shares) AS total_shares FROM transactions WHERE user_id = ? AND symbol = ?", session["user_id"], symbol)
        if not shares_owned or shares_owned[0]["total_shares"] is None or shares_owned[0]["total_shares"] < shares_count:
            return apology("you don't own that many shares", 400)

        # setting up for selling and updating database
        current_stock_price = stock["price"]
        selling_price = current_stock_price * shares_count
        db.execute("INSERT INTO transactions (user_id, symbol, shares, price) VALUES (?, ?, ?, ?)", session["user_id"], symbol, -shares_count, current_stock_price)
        db.execute("UPDATE users SET cash = cash + ? WHERE id = ?", selling_price, session["user_id"])
        return redirect("/")
