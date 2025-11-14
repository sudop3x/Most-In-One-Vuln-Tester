from flask import Flask, render_template, request, redirect, url_for, session, flash
from auth import validate_user, create_user, update_user
from scanner import scan_url
import os
import datetime

app = Flask(__name__)
app.secret_key = os.urandom(24)

scan_history = []

@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if validate_user(username, password):
            session['user'] = username
            return redirect(url_for('dashboard'))
        else:
            flash("⚠️ Invalid login!", "error")
    return render_template('login.html')

@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if 'user' not in session:
        return redirect(url_for('login'))

    section = request.args.get('section', 'scan')  

    results = []
    total_time = None
    url = None
    error = None

    if request.method == 'POST' and section == 'scan':
        url = request.form.get('url')
        if not url:
            error = "⚠️ Please enter a valid URL before starting the scan."
        else:
            results, total_time = scan_url(url)

            scan_history.append({
                "url": url,
                "results": results,
                "time": total_time,
                "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            })

    return render_template('dashboard.html',
                           section=section,
                           results=results,
                           url=url,
                           total_time=total_time,
                           error=error,
                           scan_history=scan_history)

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('login'))


@app.route('/profile', methods=['GET', 'POST'])
def profile_page():
    if 'user' not in session:
        return redirect(url_for('login'))

    message = None

    if request.method == 'POST':
        action = request.form.get("action")
        username = request.form.get("username")
        password = request.form.get("password")

        if action == "create":
            if create_user(username, password):
                message = f"✅ User '{username}' created successfully."
            else:
                message = f"⚠ Could not create user. Maybe it already exists."
        elif action == "update":
            if update_user(username, password):
                message = f"✅ Password for '{username}' updated successfully."
            else:
                message = f"⚠ Could not update password. User may not exist."

    return render_template("profile.html", current_user=session['user'], message=message)

if __name__ == "__main__":
    app.run(debug=True)
