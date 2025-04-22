from flask import Flask, Response, flash, render_template, request, session, redirect, url_for
import sqlite3

app = Flask(__name__)
app.secret_key = 'secret_key'

# Database initialization
def init_db():
    conn = sqlite3.connect('atm.db')
    cursor = conn.cursor()
    
    # First, check if the users table exists and if it has the is_admin column
    cursor.execute("PRAGMA table_info(users)")
    columns = [column[1] for column in cursor.fetchall()]
    
    # Create or alter the users table
    if 'is_admin' not in columns:
        # If table exists but doesn't have is_admin column, add it
        if 'users' in [table[0] for table in cursor.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]:
            cursor.execute('ALTER TABLE users ADD COLUMN is_admin INTEGER DEFAULT 0')
        else:
            # Create new table with all columns
            cursor.execute('''
                CREATE TABLE users (
                    username TEXT PRIMARY KEY,
                    password TEXT NOT NULL,
                    atm_pin TEXT NOT NULL,
                    balance REAL NOT NULL DEFAULT 0,
                    is_admin INTEGER DEFAULT 0
                )
            ''')
    
    # Create transactions table if it doesn't exist
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            transaction_type TEXT NOT NULL,
            amount REAL NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (username) REFERENCES users (username)
        )
    ''')
    
    # Check if admin user exists, if not create one
    cursor.execute('SELECT username FROM users WHERE is_admin = 1')
    if not cursor.fetchone():
        cursor.execute('INSERT INTO users (username, password, atm_pin, is_admin) VALUES (?, ?, ?, ?)',
                      ('admin', 'admin123', '0000', 1))
    
    conn.commit()
    conn.close()

# Initialize the database
init_db()

def get_user(username):
    conn = sqlite3.connect('atm.db')
    cursor = conn.cursor()
    cursor.execute('SELECT username, password, atm_pin, is_admin FROM users WHERE username = ?', (username,))
    user = cursor.fetchone()
    conn.close()
    return user

def add_user(username, password, atm_pin):
    conn = sqlite3.connect('atm.db')
    cursor = conn.cursor()
    cursor.execute('INSERT INTO users (username, password, atm_pin) VALUES (?, ?, ?)', (username, password, atm_pin))
    conn.commit()
    conn.close()

def update_balance(username, amount):
    conn = sqlite3.connect('atm.db')
    cursor = conn.cursor()
    cursor.execute('UPDATE users SET balance = balance + ? WHERE username = ?', (amount, username))
    conn.commit()
    conn.close()

def get_balance(username):
    conn = sqlite3.connect('atm.db')
    cursor = conn.cursor()
    cursor.execute('SELECT balance FROM users WHERE username = ?', (username,))
    balance = cursor.fetchone()[0]
    conn.close()
    return balance

def log_transaction(username, transaction_type, amount):
    conn = sqlite3.connect('atm.db')
    cursor = conn.cursor()
    cursor.execute('INSERT INTO transactions (username, transaction_type, amount) VALUES (?, ?, ?)', (username, transaction_type, amount))
    conn.commit()
    conn.close()

def get_transactions(username):
    conn = sqlite3.connect('atm.db')
    cursor = conn.cursor()
    cursor.execute('SELECT transaction_type, amount, timestamp FROM transactions WHERE username = ?', (username,))
    transactions = cursor.fetchall()
    conn.close()
    return transactions

def get_all_users():
    conn = sqlite3.connect('atm.db')
    cursor = conn.cursor()
    cursor.execute('SELECT username FROM users')
    users = cursor.fetchall()
    conn.close()
    return [user[0] for user in users]  # Extract usernames from tuples

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = get_user(username)
        if user:
            if user[1] == password:  # Check password
                session['username'] = username
                session['user_name'] = username
                session['is_admin'] = bool(user[3]) if len(user) > 3 else False  # Check is_admin flag
                if session['is_admin']:
                    return redirect(url_for('admin'))
                else:
                    return redirect(url_for('dashboard'))
            else:
                error = 'Invalid credentials'
        else:
            error = 'Invalid credentials'
    
    return render_template('login.html', error=error)

@app.route('/admin')
def admin():
    if 'username' not in session or not session.get('is_admin', False):
        return redirect(url_for('login'))
    return render_template('admin.html', users=get_all_users())

@app.route('/add_user', methods=['POST'])
def add_user_route():
    if 'username' not in session or not session.get('is_admin', False):
        return redirect(url_for('login'))
    
    username = request.form['username']
    password = request.form['password']
    atm_pin = request.form['atm_pin']
    
    # Check if the username already exists
    if get_user(username):
        flash('User already exists', 'error')  # Use flash for better user feedback
        return redirect(url_for('admin'))  # Redirect back to the admin page after adding

    add_user(username, password, atm_pin)  # Call the function to add the user
    flash('User created successfully!', 'success')  # Notify success
    return redirect(url_for('admin'))  # Redirect back to the admin page after adding

@app.route('/transactions', methods=['GET'])
def transactions():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    username = session['username']
    transactions = get_transactions(username)  # Fetch transactions for the logged-in user
    return render_template('transactions.html', transactions=transactions)  # Render a transactions template

@app.route('/download_transactions', methods=['GET'])
def download_transactions():
    if 'username' not in session:
        return redirect(url_for('login'))

    username = session['username']
    transactions = get_transactions(username)  # Fetch transactions for the logged-in user

    # Create a CSV response
    def generate():
        yield 'Transaction Type,Amount,Timestamp\n'  # CSV Header
        for transaction in transactions:
            yield f"{transaction[0]},{transaction[1]},{transaction[2]}\n"

    return Response(generate(), mimetype='text/csv', headers={"Content-Disposition": "attachment;filename=transactions.csv"})

@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    username = session['username']
    user_name = session['user_name']  # Fetch the user's name from the session
    balance = get_balance(username)
    transactions = get_transactions(username)
    
    return render_template('dashboard.html', user_name=user_name, balance=balance, transactions=transactions)

@app.route('/deposit', methods=['POST'])
def deposit():
    if 'username' not in session:
        return redirect(url_for('login'))
    username = session['username']
    amount = int(request.form['amount'])
    atm_pin = request.form['atm_pin']

    user = get_user(username)
    if atm_pin != user[2]:
        return 'Invalid ATM PIN', 400

    update_balance(username, amount)
    log_transaction(username, 'deposit', amount)
    return redirect(url_for('dashboard'))

@app.route('/withdraw', methods=['POST'])
def withdraw():
    if 'username' not in session:
        return redirect(url_for('login'))
    username = session['username']
    amount = int(request.form['amount'])
    atm_pin = request.form['atm_pin']

    user = get_user(username)
    if atm_pin != user[2]:
        return 'Invalid ATM PIN', 400

    balance = get_balance(username)
    if amount > balance:
        return 'Insufficient balance', 400

    update_balance(username, -amount)
    log_transaction(username, 'withdrawal', amount)
    return redirect(url_for('dashboard'))

@app.route('/logout', methods=['POST'])
def logout():
    session.clear()  # Clear the session
    return redirect(url_for('login'))  # Redirect to the login page

@app.route('/change_admin_credentials', methods=['POST'])
def change_admin_credentials():
    if 'username' not in session or not session.get('is_admin', False):
        return redirect(url_for('login'))
    
    current_password = request.form['current_password']
    new_username = request.form['new_username']
    new_password = request.form['new_password']
    
    # Verify current admin credentials
    conn = sqlite3.connect('atm.db')
    cursor = conn.cursor()
    cursor.execute('SELECT password FROM users WHERE is_admin = 1')
    current_admin = cursor.fetchone()
    
    if not current_admin or current_admin[0] != current_password:
        flash('Current password is incorrect', 'error')
        return redirect(url_for('admin'))
    
    # Update admin credentials
    cursor.execute('UPDATE users SET username = ?, password = ? WHERE is_admin = 1',
                  (new_username, new_password))
    conn.commit()
    conn.close()
    
    flash('Admin credentials updated successfully!', 'success')
    return redirect(url_for('admin'))

@app.route('/delete_user', methods=['POST'])
def delete_user():
    if 'username' not in session or not session.get('is_admin', False):
        return redirect(url_for('login'))
    
    username = request.form['username']
    
    # Don't allow deleting the admin user
    if username == 'admin':
        flash('Cannot delete the admin user', 'error')
        return redirect(url_for('admin'))
    
    conn = sqlite3.connect('atm.db')
    cursor = conn.cursor()
    
    # Delete user's transactions first (due to foreign key constraint)
    cursor.execute('DELETE FROM transactions WHERE username = ?', (username,))
    # Then delete the user
    cursor.execute('DELETE FROM users WHERE username = ?', (username,))
    
    conn.commit()
    conn.close()
    
    flash(f'User {username} deleted successfully!', 'success')
    return redirect(url_for('admin'))

if __name__ == '__main__':
    app.run(debug=True)
