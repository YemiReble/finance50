import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session, url_for
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import (
    apology, login_required,
    lookup, usd, record_update_purchase,
    sell_shares, stocks_symbols
    )

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
    # Get User
    user = session["user_id"]
    symbols = stocks_symbols()
    query = f"""
        SELECT u.cash, p.symbol, SUM(p.shares) AS total_shares
        FROM users u
        LEFT JOIN purchases p ON u.id = p.user_id
        WHERE u.id = {user}
        GROUP BY p.symbol
    """
    
    result = db.execute(query)

    if result is None:
        return render_template(
            "index.html", cash=result[0]["cash"],
            holdings=0, grand_total=0,
            available_stocks=symbols
        )

    if result[0]["symbol"] is None:
        return render_template(
            "index.html", cash=result[0]["cash"],
            holdings=[], grand_total=0,
            available_stocks=symbols
        )
    
    stocks = []
    grand_total = 0
    
    for row in result:
        stock = dict(row)
        
        # Fetch real-time stock data using the lookup function
        current_price = lookup(stock["symbol"])
        cp = current_price["price"]
        
        total_value = float(cp) * float(stock["total_shares"])
        stock["current_price"] = cp
        stock["shares"] = stock["total_shares"]
        stock["total_value"] = total_value
        grand_total += total_value
        
        stocks.append(stock)

    return render_template(
        "index.html", cash=result[0]["cash"],
        holdings=stocks, grand_total=grand_total,
        available_stocks=symbols
    )


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == 'POST':
        symbol = request.form.get('symbol').strip().upper()
        shares = request.form.get('shares').strip()

        # Validate inputs
        if not symbol:
            return apology("Please enter a stock symbol.", 400)
        
        if not shares.isdigit() or int(shares) <= 0:
            return apology("Please enter a positive integer for shares.", 400)

        shares = int(shares)
        stock = lookup(symbol) # Looking up stock validity

        if not stock:
            return apology("Stock symbol does not exist.", 400)

        price = stock['price']
        user_id = session["user_id"]

        # Check if user can afford the purchase
        query = "SELECT cash FROM users WHERE id = ?"
        cash = db.execute(query, (user_id,))
        cash = cash[0]["cash"]

        total_cost = price * shares
        
        if cash < total_cost:
            return apology("You cannot afford this purchase.", 400)

        # Deduct stock total price from user's cash
        new_balance = cash - total_cost

        # Record the purchase
        try:
            record_update_purchase(db, user_id, symbol, shares, price, new_balance)
        except ValueError as e:
            return apology(str(e), 400)

        # Redirect to home page after successful purchase
        return redirect('/')

        # return apology("TODO")
    return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    user_id = session["user_id"]
    query = db.execute("""
            SELECT transaction_type, symbol, shares, price, timestamp
            FROM history
            WHERE user_id = ?
            ORDER BY timestamp DESC
        """, (user_id,))

    return render_template("history.html", transactions=query)


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
    if request.method == "POST":
        try:
            user_input = request.form.get("symbol")
            stock = lookup(user_input)
            return render_template("quoted.html", stock=stock)

        except Exception as e:
            return apology(str(e))

    return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":
        try:
            username = request.form.get("username")
            password = request.form.get("password")

            if not username:
                return apology("Username can not be empty!", 400)

            elif not password:
                return apology("Password can not be empty!", 400)

            hashed_password = generate_password_hash(password)
            db.execute("INSERT INTO users (username, hash) VALUES (?)", (username, hashed_password))
            # db.commit()
            return redirect(url_for("login"))
        except Exception as e:
            return apology(str(e))

    # return apology("TODO")
    return render_template("signup.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    user = session["user_id"]
    query = f"""
        SELECT p.symbol, SUM(p.shares) AS shares, u.cash, SUM(p.shares) AS total_shares
        FROM users u
        LEFT JOIN purchases p ON u.id = p.user_id
        WHERE u.id = ?
        GROUP BY p.symbol;
    """
    stocks = db.execute(query, (user))
    if request.method == "POST":
        symbol = request.form.get("symbol") #.upper()
        shares = request.form.get("shares").strip()

        if not symbol or not shares:
            return apology("A symbol and shares size is required!", 400)

        shares = int(shares)

        # Check if user owns enough shares
        owned_shares = next((stock['shares'] for stock in stocks if stock['symbol'] == symbol), 0)

        if owned_shares < shares:
            return apology("You do not own that many shares of the selected stock.", 400)

        stock = lookup(symbol)
        current_value = stock["price"]
        balance = stocks[0]["cash"]
        new_balance = (shares * current_value) + balance
        sell_shares(db, user, symbol=str(symbol), shares=shares, new_balance=new_balance)

        # Redirect to home page after successful sale
        flash("Sale completed successfully!")
        return redirect('/')
    # return apology("TODO")
    return render_template("sell.html", holdings=stocks)


@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    """Change user's Password"""
    user_id = session.get("user_id")

    if request.method == 'POST':
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        # Validate input
        row = db.execute("SELECT hash FROM users WHERE id = ?", (user_id,))
        if not row or not check_password_hash(row[0]['hash'], current_password):
            return render_template('change_password.html', error="Current password is incorrect.")

        if new_password != confirm_password:
            return render_template('change_password.html', error="New passwords do not match.")

        if len(new_password) < 6:
            return render_template('change_password.html', error="New password must be at least 6 characters long.")

        # Update the password in the database
        try:
            hashed_password = generate_password_hash(new_password)
            db.execute(f"UPDATE users SET hash = '{hashed_password}' WHERE id = ?", (user_id))
        except Exception as e:
            return apology(f"Something went wrong while trying to update password: {str(e)}", 400)

        flash("Password changed successfully!")
        return redirect('/')

    return render_template("change_password.html")


@app.route('/add_cash', methods=['POST'])
@login_required
def add_cash():
    """Add Cash"""
    user_id = session.get("user_id")
    additional_cash = request.form.get('additional_cash', type=float)

    # Update the user's cash balance in the database
    db.execute(
        f"UPDATE users SET cash = cash + {additional_cash} WHERE id = {user_id}")

    flash("Cash added successfully!")
    return redirect('/')


@app.route('/profile', methods=['POST', 'GET'])
@login_required
def profile():
    """User Profile view"""
    user_id = session["user_id"]
    user = db.execute(
        f"SELECT u.username, u.cash FROM users AS u WHERE id = {user_id}")
    
    symbols = stocks_symbols()
    return render_template(
        "profile.html",
        username=user[0]["username"],
        cash=float(user[0]["cash"]),
        available_stocks=symbols
    )


@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    """User Reset Password"""
    if request.method == 'POST':
        username = request.form.get('username')
        reset_code = request.form.get('reset_code')
        new_password = request.form.get('new_password')

        if username is not None and reset_code.isdigit():
            user = db.execute("SELECT username, hash FROM users WHERE username = ?", (username))
            if user is None:
                return render_template('reset_password.html', error="User with this username not found")

            if check_password_hash(user[0]['hash'], new_password):
                flash("Please choose a different password than your current one.", "error")
                return render_template('reset_password.html')

            hashed_password = generate_password_hash(new_password)
            db.execute(f"UPDATE users SET hash = '{hashed_password}' WHERE username = ?", (username))
            flash("Your password has been reset successfully.")
            return redirect('/login')
        else:
            return render_template('reset_password.html', error="Invalid reset code or username.")

    return render_template('reset_password.html')


@app.errorhandler(404)
def page_not_found(e):
    """Page Not Found handler"""
    return render_template('404.html'), 404


@app.errorhandler(500)
def internal_server_error(e):
    """Server Error"""
    return render_template('500.html'), 500


if __name__ == "__main__":
    app.run(host="localhost", port=5000, debug=True)
