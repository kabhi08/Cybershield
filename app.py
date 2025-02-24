from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from flask_session import Session
import datetime
import socket
import requests
import os
from werkzeug.utils import secure_filename    
import smtplib
from email.message import EmailMessage
import pyotp

app = Flask(__name__)
app.secret_key = "52c1cb47557cba9c1d8db964c887641b91bb24b772183c9ad9e479d833af94b8e50397bebd49afc626e9a54daeb122972fdb262b2d59965c9aff47b1a5b99272"

# Session Configuration
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Database Connection
def get_db_connection():
    conn = sqlite3.connect("security.db")
    conn.row_factory = sqlite3.Row
    return conn

# Create Tables if Not Exist
def create_tables():
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute('''CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT NOT NULL UNIQUE,
                        email TEXT NOT NULL UNIQUE,
                        password TEXT NOT NULL,
                        is_admin INTEGER DEFAULT 0
                      )''')

    cursor.execute('''CREATE TABLE IF NOT EXISTS policies (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        title TEXT NOT NULL UNIQUE,
                        description TEXT NOT NULL,
                        long_description TEXT,
                        advantages TEXT,
                        disadvantages TEXT
                      )''')

    cursor.execute('''CREATE TABLE IF NOT EXISTS businesses (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        name TEXT NOT NULL,
                        url TEXT NOT NULL,
                        applied_policy INTEGER,
                        FOREIGN KEY (applied_policy) REFERENCES policies (id)
                      )''')

    conn.commit()
    conn.close()

def update_policy_data():
    conn = sqlite3.connect("security.db")  # Connect to the database
    cursor = conn.cursor()

    updates = [
        (26, "Data Protection Policy ensures the security, confidentiality, and integrity of sensitive data. It includes measures such as encryption, access control, and data retention policies. Organizations must comply with regulatory frameworks like GDPR and HIPAA to prevent data leaks and unauthorized access. This policy enforces secure data handling practices and ensures proper risk mitigation in case of breaches.",
         "Prevents data leaks, Ensures compliance, Strengthens security, Enhances privacy, Supports legal regulations",
         "Can be expensive to implement, Requires regular audits, Complex setup, Time-consuming enforcement, Employee training needed"),
         
        (27, "Password Management Policy mandates strong password creation, rotation, and storage best practices. It prevents unauthorized access by enforcing multi-factor authentication and password expiration policies. Users are required to maintain secure credentials, avoiding weak passwords that could be easily guessed or hacked by attackers.",
         "Improves security, Reduces unauthorized access, Enforces strong credentials, Prevents brute-force attacks, Supports MFA implementation",
         "Users may forget passwords frequently, Can be difficult to enforce, Requires additional security tools, May cause login delays, Higher user support requirements"),
        
        (28, "Network Security Policy defines security measures for internal and external networks, including firewalls, VPNs, and intrusion detection systems. This policy protects an organization from cyber threats such as malware, phishing attacks, and DDoS attacks by implementing strict security rules.",
         "Enhances cybersecurity, Protects against attacks, Improves monitoring, Reduces vulnerability, Ensures compliance",
         "Can reduce network performance, Requires dedicated IT team, High initial cost, Complex firewall rules, Needs regular updates"),
        
        (29, "Access Control Policy ensures only authorized personnel can access sensitive systems and data. It includes role-based access control (RBAC), multi-factor authentication (MFA), and audit logging to track user activity. Organizations use this policy to minimize the risk of insider threats and unauthorized access.",
         "Enhances security, Reduces insider threats, Strengthens authentication, Ensures accountability, Supports regulatory compliance",
         "Can create administrative overhead, Complex to manage, Requires regular permission reviews, May slow down access, Needs automation tools"),
        
        (30, "Incident Response Policy outlines procedures for identifying, responding to, and mitigating security incidents. It helps organizations quickly contain cyber threats, recover data, and prevent further damage. A well-defined incident response strategy ensures minimal downtime and compliance with security standards.",
         "Ensures quick recovery, Reduces data loss, Improves incident tracking, Enhances forensic analysis, Strengthens business continuity",
         "Requires continuous updating, Needs trained personnel, Can be expensive, Time-consuming implementation, Dependent on external threat intelligence")
    ]

    for policy in updates:
        cursor.execute("UPDATE policies SET description = ?, advantages = ?, disadvantages = ? WHERE id = ?", (policy[1], policy[2], policy[3], policy[0]))

    conn.commit()
    conn.close()
    print("✅ Policy data updated successfully!")

# Run the function once
update_policy_data()

# Insert Default Policies (Avoid Duplicates)
def insert_default_policies():
    conn = get_db_connection()
    cursor = conn.cursor()

    policies = [
        ("Data Protection Policy", "Ensures data confidentiality and integrity.",
         "This policy covers encryption, backup policies, and access controls.",
         "Prevents data leaks, Ensures compliance", "Can be expensive to implement"),

        ("Password Management Policy", "Users must create strong passwords and update them regularly.",
         "This policy enforces password complexity, expiration, and storage best practices.",
         "Improves security, Reduces unauthorized access", "Users may forget passwords frequently"),

        ("Network Security Policy", "Defines rules for securing internal and external networks.",
         "This policy includes firewall management, VPN usage, and network segmentation.",
         "Enhances cybersecurity, Protects against attacks", "Can reduce network performance")
    ]

    for title, description, long_desc, advantages, disadvantages in policies:
        cursor.execute("SELECT COUNT(*) FROM policies WHERE title = ?", (title,))
        count = cursor.fetchone()[0]

        if count == 0:
            cursor.execute("INSERT INTO policies (title, description, long_description, advantages, disadvantages) VALUES (?, ?, ?, ?, ?)", 
                           (title, description, long_desc, advantages, disadvantages))

    conn.commit()
    conn.close()

conn = sqlite3.connect('security.db')
c = conn.cursor()

threats = [
    ("SQL Injection", "Attackers can inject SQL queries into input fields."),
    ("Cross-Site Scripting (XSS)", "Malicious scripts are injected into web pages."),
    ("Open Ports", "Unsecured open ports can be exploited."),
    ("Outdated SSL Certificates", "Weak SSL encryption can lead to data breaches."),
]

c.executemany("INSERT INTO threats (name, description) VALUES (?, ?)", threats)
conn.commit()
conn.close()

print("Threats added successfully!")

# Home Page
@app.route("/")
def index():
    return render_template("index.html")

@app.route('/home')
def home():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM policies ORDER BY id DESC LIMIT 5")
    policies = cursor.fetchall()
    conn.close()
    return render_template('home.html', policies=policies)

# Register
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username")
        email = request.form.get("email")
        password = request.form.get("password")
        hashed_password = generate_password_hash(password)

        conn = get_db_connection()
        cursor = conn.cursor()
        try:
            cursor.execute("INSERT INTO users (username, email, password) VALUES (?, ?, ?)",
                           (username, email, hashed_password))
            conn.commit()
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            flash("Username or Email already exists!", "danger")
        finally:
            conn.close()

    return render_template("register.html")

# Login
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
        user = cursor.fetchone()
        conn.close()

        if user and check_password_hash(user["password"], password):
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["is_admin"] = user["is_admin"]

            return redirect(url_for("policy_page"))
        else:
            flash("Invalid email or password!", "danger")

    return render_template("login.html")

# Dashboard
@app.route('/dashboard')
def dashboard():
    if "user_id" not in session:
        return redirect(url_for("login"))

    return render_template("dashboard.html")

# Policy Page
@app.route('/policy')
def policy_page():
    if "user_id" not in session:
        flash("You need to register or log in first.", "warning")
        return redirect(url_for("register"))

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM policies")
    policies = cursor.fetchall()
    conn.close()
    
    return render_template('policy.html', policies=policies)
@app.route('/add_policy', methods=['GET', 'POST'])
def add_policy():
    if request.method == 'POST':
        name = request.form['name']
        description = request.form['description']
        advantages = request.form['advantages']
        disadvantages = request.form['disadvantages']
        tools = request.form['tools']  # Tools associated with the policy
        
        conn = sqlite3.connect('security.db')
        c = conn.cursor()
        c.execute("INSERT INTO policies (name, description, advantages, disadvantages, tools) VALUES (?, ?, ?, ?, ?)", 
                  (name, description, advantages, disadvantages, tools))
        conn.commit()
        conn.close()
        
        flash('Policy added successfully!', 'success')
        return redirect(url_for('view_policies'))  # Redirect to policy list page

    return render_template('add_policy.html')


# Policy Details (No "Policy not found!" message)
@app.route("/policy/<int:policy_id>")
def policy_details(policy_id):
    conn = get_db_connection()
    policy = conn.execute("SELECT id, title, description, long_description, advantages, disadvantages, tools FROM policies WHERE id = ?", (policy_id,)).fetchone()
    conn.close()

    if not policy:
        flash("Policy not found!", "error")
        return redirect(url_for("home"))

    # Convert advantages & disadvantages from a single DB string to a list
    advantages = policy["advantages"].split("|") if policy["advantages"] else []
    disadvantages = policy["disadvantages"].split("|") if policy["disadvantages"] else []
    tools = policy["tools"].split(",") if policy["tools"] else []

    return render_template("policy_detail.html", policy=policy, advantages=advantages, disadvantages=disadvantages, tools=tools)

# Business Registration & Apply Policy
@app.route('/apply_policy', methods=['POST'])
def apply_policy():
    business_name = request.form['business_name']
    business_url = request.form['business_url']
    policy_name = request.form['policy_name']  # This should be a string

    conn = get_db_connection()
    cursor = conn.cursor()

    # Fetch the policy ID using policy_name
    cursor.execute("SELECT id FROM policies WHERE title = ?", (policy_name,))
    policy_id = cursor.fetchone()

    if policy_id:  # Check if policy_id is found
        policy_id = policy_id[0]  # Extract integer value
        print("DEBUG: Policy ID retrieved →", policy_id)  # Debugging line

        # Insert into businesses table
        cursor.execute("INSERT INTO businesses (name, url, applied_policy) VALUES (?, ?, ?)", 
                       (business_name, business_url, policy_id))
        conn.commit()
        flash("Policy applied successfully!", "success")
    else:
        flash("Policy not found!", "error")

    conn.close()
    return redirect(url_for('home'))

# Tools Page
@app.route('/policy/tools/<int:policy_id>', methods=['GET', 'POST'])
def policy_tools(policy_id):
    conn = get_db_connection()
    policy = conn.execute("SELECT title, tools FROM policies WHERE id = ?", (policy_id,)).fetchone()
    tools = policy['tools'].split(",") if policy['tools'] else []
    
    if request.method == 'POST':
        business_name = request.form['business_name']
        tool_name = request.form['tool_name']
        
        # Ensure URL is properly formatted
        if not business_name.startswith("http"):
            url = f"https://{business_name}"
        else:
            url = business_name

        print(f"Checking URL: {url}")  # Debugging line

        try:
            response = requests.get(url, timeout=5)
            print(f"Response Code: {response.status_code}")  # Debugging line
            
            if response.status_code == 200:
                conn.execute("INSERT INTO tool_usage (business_id, policy_id, tool_name) VALUES ((SELECT id FROM businesses WHERE name = ?), ?, ?)",
                            (business_name, policy_id, tool_name))
                conn.commit()
                flash("Policy applied successfully!", "success")
                return {"status": "success", "message": "✅ Policy Applied Successfully!"}
            else:
                return {"status": "error", "message": "❌ Website Not Found! Please enter a correct URL."}
        except requests.exceptions.RequestException as e:
            print(f"Error: {e}")  # Debugging line
            return {"status": "error", "message": "❌ Website Not Found! Please enter a correct URL."}

    return render_template('policy_tools.html', policy=policy, tools=tools)
@app.route('/tools')
def tools_dashboard():
    return render_template('tools_dashboard.html')

@app.route('/tools/encryption')
def encryption_tool():
    return render_template('encryption_tools.html')

@app.route('/tools/password-management')
def password_tools():
    return render_template('password_tools.html')
@app.route('/api/test-firewall')
def test_firewall():
    url = request.args.get('url')
    try:
        response = requests.get(f'http://{url}', timeout=5)
        if response.status_code == 200:
            return jsonify({"result": "Website is accessible (Firewall allows traffic)."})
        else:
            return jsonify({"result": "Website is blocking traffic."})
    except requests.exceptions.RequestException:
        return jsonify({"result": "Website is blocking traffic or unreachable."})

@app.route('/api/scan-ports')
def scan_ports():
    url = request.args.get('url')
    open_ports = []
    common_ports = [21, 22, 25, 53, 80, 443, 3306, 8080]  # FTP, SSH, SMTP, DNS, HTTP, HTTPS, MySQL, Alternative HTTP

    for port in common_ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((url, port))
        if result == 0:
            open_ports.append(port)
        sock.close()

    return jsonify({"open_ports": open_ports})

@app.route('/log_tool_usage', methods=['POST'])
def log_tool_usage():
    """Logs the tool usage when a user applies a tool to a website/business."""
    data = request.json
    business_name = data.get("business_name")
    policy_id = data.get("policy_id")
    tool_name = data.get("tool_name")

    if not business_name or not policy_id or not tool_name:
        return jsonify({"error": "Missing required data"}), 400

    conn = sqlite3.connect('security.db')
    cursor = conn.cursor()

    # Find the business ID
    cursor.execute("SELECT id FROM businesses WHERE name = ?", (business_name,))
    business = cursor.fetchone()

    if not business:
        return jsonify({"error": "Business not found"}), 404

    business_id = business[0]

    # Insert usage record
    cursor.execute(
        "INSERT INTO tool_usage (business_id, policy_id, tool_name, used_at) VALUES (?, ?, ?, ?)",
        (business_id, policy_id, tool_name, datetime.datetime.now())
    )
    
    conn.commit()
    conn.close()

    return jsonify({"success": "Tool usage logged successfully!"}), 200

ALLOWED_EXTENSIONS = {'log', 'txt'}
UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

@app.route('/tools/incident-response')
def incident_tools():
    return render_template('incident_tools.html')

@app.route('/api/check-phishing')
def check_phishing():
    url = request.args.get('url')
    try:
        # Using an open API for phishing detection (Example: PhishTank, OpenPhish)
        response = requests.get(f"https://checkphish.ai/api/v1/{url}")
        data = response.json()
        
        if data.get("status") == "phishing":
            return jsonify({"result": "⚠️ This URL is flagged as a phishing site!"})
        else:
            return jsonify({"result": "✅ This URL seems safe."})
    
    except requests.exceptions.RequestException:
        return jsonify({"result": "⚠️ Unable to check this URL."})

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/api/analyze-logs', methods=['POST'])
def analyze_logs():
    if 'file' not in request.files:
        return jsonify({"result": "No file uploaded!"})

    file = request.files['file']
    if file.filename == '':
        return jsonify({"result": "No file selected!"})

    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file_path = os.path.join(UPLOAD_FOLDER, filename)
        file.save(file_path)

        # Scan the file for suspicious patterns (e.g., failed login attempts)
        suspicious_patterns = ["failed login", "unauthorized access", "error 403", "brute force"]
        suspicious_entries = []

        with open(file_path, "r") as log_file:
            for line in log_file:
                if any(pattern in line.lower() for pattern in suspicious_patterns):
                    suspicious_entries.append(line.strip())

        if suspicious_entries:
            return jsonify({"result": f"⚠️ Found {len(suspicious_entries)} suspicious entries!"})
        else:
            return jsonify({"result": "✅ No suspicious activity detected."})
        
@app.route('/tools/cyber-threat')
def cyber_threat_tools():
    return render_template('cyber_threat_tools.html')

@app.route('/api/check-ip')
def check_ip():
    ip = request.args.get('ip')
    try:
        # Example API for checking IP reputation (Replace with a real API)
        response = requests.get(f"https://ipinfo.io/{ip}/json")
        data = response.json()

        if "bogon" in data or "abuse" in data.get("tags", []):
            return jsonify({"result": "⚠️ This IP is flagged as suspicious!"})
        else:
            return jsonify({"result": "✅ This IP is safe."})

    except requests.exceptions.RequestException:
        return jsonify({"result": "⚠️ Unable to check this IP."})

@app.route('/api/check-dark-web')
def check_dark_web():
    email = request.args.get('email')
    try:
        # Example API for checking dark web breaches (Replace with a real API)
        response = requests.get(f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}")
        
        if response.status_code == 200:
            return jsonify({"result": "⚠️ This email has been found in data breaches!"})
        else:
            return jsonify({"result": "✅ No breaches found for this email."})

    except requests.exceptions.RequestException:
        return jsonify({"result": "⚠️ Unable to check dark web status."})
    
active_sessions = [
    {"user": "admin", "ip": "192.168.1.10", "last_active": "2025-02-21 10:30 AM"},
    {"user": "guest", "ip": "192.168.1.15", "last_active": "2025-02-21 10:45 AM"}
]

@app.route('/tools/access-control')
def access_control_tools():
    return render_template('access_control_tools.html')

@app.route('/api/generate-2fa')
def generate_2fa():
    secret = request.args.get('secret')
    if not secret:
        return jsonify({"error": "Secret key is required"}), 400
    totp = pyotp.TOTP(secret)
    return jsonify({"code": totp.now()})

@app.route('/api/check-sessions')
def check_sessions():
    return jsonify({"sessions": active_sessions})


def init_db():
    conn = sqlite3.connect('security.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS incidents (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    title TEXT NOT NULL,
                    description TEXT NOT NULL,
                    date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )''')
    conn.commit()
    conn.close()

init_db()

@app.route('/tools/incident-response')
def incident_response_tools():
    return render_template('incident_response_tools.html')

@app.route('/api/log-incident', methods=['POST'])
def log_incident():
    data = request.json
    title = data.get('title')
    description = data.get('description')

    if not title or description:
        return jsonify({"error": "Title and description are required"}), 400

    conn = sqlite3.connect('security.db')
    c = conn.cursor()
    c.execute("INSERT INTO incidents (title, description) VALUES (?, ?)", (title, description))
    conn.commit()
    conn.close()

    send_alert(title, description)  # Send email alert

    return jsonify({"message": "Incident logged successfully!"})

@app.route('/api/get-incidents')
def get_incidents():
    conn = sqlite3.connect('security.db')
    c = conn.cursor()
    c.execute("SELECT title, description, date FROM incidents ORDER BY date DESC")
    incidents = [{"title": row[0], "description": row[1], "date": row[2]} for row in c.fetchall()]
    conn.close()

    return jsonify({"incidents": incidents})

# Send Email Alert
def send_alert(title, description):
    sender_email = "your_email@example.com"
    receiver_email = "admin@example.com"
    subject = f"🚨 Security Incident Reported: {title}"
    body = f"A new security incident has been reported.\n\nTitle: {title}\nDescription: {description}\n\nCheck system logs for details."

    msg = EmailMessage()
    msg.set_content(body)
    msg["Subject"] = subject
    msg["From"] = sender_email
    msg["To"] = receiver_email

    try:
        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()
        server.login("your_email@example.com", "your_app_password")
        server.send_message(msg)
        server.quit()
        print("Email alert sent!")
    except Exception as e:
        print("Failed to send email:", e)

@app.route('/admin/tool_usage')
def tool_usage_dashboard():
    """Shows tool usage history for the admin."""
    conn = sqlite3.connect('security.db')
    cursor = conn.cursor()

    cursor.execute("""
        SELECT businesses.name, policies.name, tool_usage.tool_name, tool_usage.used_at
        FROM tool_usage
        JOIN businesses ON tool_usage.business_id = businesses.id
        JOIN policies ON tool_usage.policy_id = policies.id
        ORDER BY tool_usage.used_at DESC
    """)
    
    usage_data = cursor.fetchall()
    conn.close()

    return render_template('admin/tool_usage.html', usage_data=usage_data)
# Search Businesses by Policy
@app.route('/search', methods=['GET', 'POST'])
def search_businesses():
    """Search businesses that applied specific policies"""
    conn = sqlite3.connect('security.db')
    cursor = conn.cursor()

    # Fetch all policies for dropdown
    cursor.execute("SELECT id, name FROM policies")
    policies = cursor.fetchall()

    # Check if a policy ID was submitted for searching
    policy_id = request.args.get('policy_id')
    businesses = []

    if policy_id:
        cursor.execute("""
            SELECT businesses.id, businesses.name, businesses.url, policies.name
            FROM businesses
            JOIN policies ON businesses.applied_policy = policies.id
            WHERE businesses.applied_policy = ?
        """, (policy_id,))
        businesses = cursor.fetchall()

    conn.close()
    return render_template('search.html', policies=policies, businesses=businesses)


# Edit Policy for a Business
@app.route('/edit_policy/<int:business_id>', methods=['GET', 'POST'])
def edit_policy(business_id):
    """Allow a business to update its applied security policy"""
    conn = sqlite3.connect('security.db')
    cursor = conn.cursor()

    if request.method == 'POST':
        new_policy_id = request.form['policy_id']
        cursor.execute("UPDATE businesses SET applied_policy = ? WHERE id = ?", (new_policy_id, business_id))
        conn.commit()
        conn.close()
        flash("Policy updated successfully!", "success")
        return redirect(url_for('search_businesses'))  # Redirect to search page after update

    # Fetch current business data
    cursor.execute("SELECT id, name, applied_policy FROM businesses WHERE id = ?", (business_id,))
    business = cursor.fetchone()

    # Fetch all policies for dropdown
    cursor.execute("SELECT id, name FROM policies")
    policies = cursor.fetchall()

    conn.close()
    return render_template('edit_policy.html', business=business, policies=policies)


# Logout
@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

if __name__ == "__main__":
    create_tables()  # Ensure tables exist before running
    insert_default_policies()  # Add predefined policies
    from waitress import serve
    serve(app, host="0.0.0.0", port=5000)
    app.run(debug=True)
