import requests

from flask import redirect, render_template, session
from functools import wraps


def apology(message, code=400):
    """Render message as an apology to user."""

    def escape(s):
        """
        Escape special characters.

        https://github.com/jacebrowning/memegen#special-characters
        """
        for old, new in [
            ("-", "--"),
            (" ", "-"),
            ("_", "__"),
            ("?", "~q"),
            ("%", "~p"),
            ("#", "~h"),
            ("/", "~s"),
            ('"', "''"),
        ]:
            s = s.replace(old, new)
        return s

    return render_template("apology.html", top=code, bottom=escape(message)), code


def login_required(f):
    """
    Decorate routes to require login.

    https://flask.palletsprojects.com/en/latest/patterns/viewdecorators/
    """

    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("user_id") is None:
            return redirect("/login")
        return f(*args, **kwargs)

    return decorated_function


def lookup(symbol):
    """Look up quote for symbol."""
    url = f"https://finance.cs50.io/quote?symbol={symbol.upper()}"
    try:
        response = requests.get(url)
        response.raise_for_status()  # Raise an error for HTTP error responses
        quote_data = response.json()
        return {
            "name": quote_data["companyName"],
            "price": quote_data["latestPrice"],
            "symbol": symbol.upper()
        }
    except requests.RequestException as e:
        print(f"Request error: {e}")
    except (KeyError, ValueError) as e:
        print(f"Data parsing error: {e}")
    return None


def usd(value):
    """Format value as USD."""
    return f"${value:,.2f}"


def record_update_purchase(db, user_id, symbol, shares, price, new_balance):
    """Function to record the purchase in the database"""
    try:
        # Check if the user already has a purchase for the same stock
        existing_purchase = db.execute(f"""
            SELECT * FROM purchases 
            WHERE user_id = {user_id} AND symbol = '{symbol}'
        """
        )
        print(existing_purchase, "Existing Purch")

        if existing_purchase:
            # Update the shares value for the existing purchase
            new_shares = existing_purchase[0]["shares"] + shares
            db.execute(f"""
                UPDATE purchases 
                SET shares = {new_shares}
                WHERE user_id = {user_id} AND symbol = '{symbol}'
            """
            )
        else:
            # Insert a new purchase if the user doesn't have an existing one
            db.execute("""
                INSERT INTO purchases (user_id, symbol, shares, price, timestamp) 
                VALUES (?, CURRENT_TIMESTAMP)
            """, (user_id, symbol, shares, price))

        # Update user's cash balance
        db.execute(f"UPDATE users SET cash = {new_balance} WHERE id = {user_id}")

        # Insert into history table
        db.execute("""
            INSERT INTO history (user_id, symbol, shares, price, transaction_type)
            VALUES (?, 'buy')
        """, (user_id, symbol, shares, price))

    except Exception as e:
        # When an operation failed
       raise ValueError(f"An error occurred: {e}")


def sell_shares(db, user_id, symbol, shares, new_balance):
    """Sell shares and update all related tables"""
    db.execute(
        f"""
        UPDATE purchases 
        SET shares = shares - {shares} 
        WHERE symbol = '{symbol}' AND user_id = {user_id}
        """
    )
    # Update user balance
    db.execute(f"UPDATE users SET cash = {new_balance} WHERE id = {session["user_id"]}")
    db.execute(f"""
            INSERT INTO history (user_id, symbol, shares, price, transaction_type)
            SELECT {user_id}, symbol, {shares}, price, 'sell'
            FROM purchases
            WHERE user_id = {user_id} AND symbol = '{symbol}'
        """
    )

    # Delete if shares reach zero after update
    db.execute(
        f"""
        DELETE FROM purchases 
        WHERE user_id = {user_id} AND symbol = '{symbol}' AND shares = 0
        """
    )


def stocks_symbols():
    """Return Stocks Symbols User's can buy"""
    symbols = ['AAPL', 'MSFT', 'AMZN',
        'GOOG', 'GOOGL', 'TSLA',
        'JNJ', 'JPM', 'V', 'META', 'UNH',
        'XOM', 'NVDA', 'PG', 'HD', 'WMT',
        'VZ', 'MA', 'KO', 'DIS', 'CVX', 'MRK',
        'MCD', 'CRM', 'PFE', 'INTC', 'PEP',
        'CSCO', 'LIN', 'GO', 'NFLX', 'ALL',
    ]
    return symbols
