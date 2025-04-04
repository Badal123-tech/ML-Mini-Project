from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
from functools import wraps

app = Flask(__name__)
app.secret_key = 'd1a2b3c4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0'

# Top 10 important questions from your analysis
TOP_QUESTIONS = [
    "Nervous",
    "Dizzy or lightheaded",
    "Numbness or tingling",
    "Hot / cold sweats",
    "Face flushed",
    "Unable to relax",
    "Fear of worst happening",
    "Heart pounding/racing",
    "Terrified or afraid",
    "Feeling of choking"
]

# Database setup
def get_db_connection():
    conn = sqlite3.connect('bai.db')
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    conn.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            full_name TEXT
        )
    ''')
    conn.execute('''
        CREATE TABLE IF NOT EXISTS test_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            total_score INTEGER NOT NULL,
            severity TEXT NOT NULL,
            test_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    conn.commit()
    conn.close()

# Login required decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        full_name = request.form['full_name']

        conn = get_db_connection()
        try:
            conn.execute(
                "INSERT INTO users (username, password, email, full_name) VALUES (?, ?, ?, ?)",
                (username, generate_password_hash(password), email, full_name)
            )
            conn.commit()
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username or email already exists.', 'danger')
        finally:
            conn.close()

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        conn.close()

        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['full_name'] = user['full_name']
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password.', 'danger')

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    conn = get_db_connection()
    tests = conn.execute(
        'SELECT * FROM test_results WHERE user_id = ? ORDER BY test_date DESC',
        (session['user_id'],)
    ).fetchall()
    conn.close()
    return render_template('dashboard.html', tests=tests)

@app.route('/test', methods=['GET', 'POST'])
@login_required
def test():
    if request.method == 'POST':
        # Calculate scores
        total_score = 0
        top_questions_score = 0

        for question in TOP_QUESTIONS:
            score = int(request.form.get(question, 0))
            total_score += score
            if question in TOP_QUESTIONS:
                top_questions_score += score

        # Determine severity
        if total_score >= 29 or (top_questions_score > 20 and total_score < 29):
            severity = "High/Severe Anxiety"
        elif 20 <= total_score <= 28:
            severity = "Moderate Anxiety"
        elif 14 <= total_score <= 19:
            severity = "Mild Anxiety"
        else:
            severity = "No or Minimal Anxiety"

        # Save results to database
        conn = get_db_connection()
        conn.execute(
            'INSERT INTO test_results (user_id, total_score, severity) VALUES (?, ?, ?)',
            (session['user_id'], total_score, severity)
        )
        conn.commit()
        conn.close()

        return render_template('results.html',
                            total_score=total_score,
                            severity=severity,
                            top_questions_score=top_questions_score)

    return render_template('test.html', questions=TOP_QUESTIONS)

if __name__ == '__main__':
    init_db()
    app.run(debug=True)