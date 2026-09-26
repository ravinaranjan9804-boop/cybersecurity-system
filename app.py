from flask import Flask, render_template, request, redirect, session, flash
import sqlite3
import os
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

app = Flask(__name__)

DATABASE = "database.db"

app.secret_key = os.environ.get("FLASK_SECRET_KEY")
if not app.secret_key:
    raise RuntimeError("FLASK_SECRET_KEY must be set before starting the application.")


# ==================================================
# DATABASE CONNECTION
# ==================================================

def get_db_connection():

    conn = sqlite3.connect(DATABASE)

    conn.row_factory = sqlite3.Row

    return conn


# ==================================================
# LOGIN REQUIRED
# ==================================================

def login_required(route_function):

    @wraps(route_function)
    def decorated_function(*args, **kwargs):

        if "user_id" not in session:

            return redirect("/login")

        return route_function(*args, **kwargs)

    return decorated_function


# ==================================================
# DATABASE INITIALIZATION
# ==================================================

def init_db():

    conn = get_db_connection()


    # USERS

    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            username TEXT UNIQUE NOT NULL,

            password_hash TEXT NOT NULL,

            role TEXT NOT NULL DEFAULT 'Admin',

            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP

        )
    """)


    # INCIDENTS

    conn.execute("""
        CREATE TABLE IF NOT EXISTS incidents (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            incident_type TEXT NOT NULL,

            description TEXT NOT NULL,

            severity TEXT NOT NULL,

            status TEXT NOT NULL,

            reported_by TEXT NOT NULL,

            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP

        )
    """)


    # POLICIES

    conn.execute("""
        CREATE TABLE IF NOT EXISTS policies (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            title TEXT NOT NULL,

            description TEXT NOT NULL,

            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP

        )
    """)


    # BUSINESS CONTINUITY

    conn.execute("""
        CREATE TABLE IF NOT EXISTS continuity (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            business_function TEXT NOT NULL,

            priority TEXT NOT NULL,

            max_downtime TEXT NOT NULL,

            recovery_procedure TEXT NOT NULL,

            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP

        )
    """)


    # DISASTER RECOVERY

    conn.execute("""
        CREATE TABLE IF NOT EXISTS disaster_recovery (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            system_name TEXT NOT NULL,

            rto TEXT NOT NULL,

            rpo TEXT NOT NULL,

            backup_location TEXT NOT NULL,

            recovery_procedure TEXT NOT NULL,

            recovery_status TEXT NOT NULL,

            last_tested TEXT NOT NULL,

            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP

        )
    """)


    # BACKUPS

    conn.execute("""
        CREATE TABLE IF NOT EXISTS backups (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            backup_name TEXT NOT NULL,

            system_name TEXT NOT NULL,

            backup_type TEXT NOT NULL,

            backup_location TEXT NOT NULL,

            frequency TEXT NOT NULL,

            last_backup TEXT NOT NULL,

            backup_status TEXT NOT NULL,

            restore_test TEXT NOT NULL,

            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP

        )
    """)


    conn.commit()

    conn.close()


# ==================================================
# DEFAULT ADMIN
# ==================================================

def create_default_admin():

    conn = get_db_connection()


    user = conn.execute(
        "SELECT id FROM users WHERE username = ?",
        ("admin",)
    ).fetchone()


    if user is None:

        initial_admin_password = os.environ.get("INITIAL_ADMIN_PASSWORD")
        if not initial_admin_password:
            conn.close()
            raise RuntimeError(
                "INITIAL_ADMIN_PASSWORD must be set when creating the initial admin account."
            )

        password_hash = generate_password_hash(
            initial_admin_password
        )


        conn.execute("""
            INSERT INTO users
            (
                username,
                password_hash,
                role
            )
            VALUES (?, ?, ?)
        """, (

            "admin",

            password_hash,

            "Admin"

        ))


    conn.commit()

    conn.close()


# ==================================================
# LOGIN
# ==================================================

@app.route("/login", methods=["GET", "POST"])
def login():

    if "user_id" in session:

        return redirect("/")


    if request.method == "POST":

        username = request.form["username"].strip()

        password = request.form["password"]


        conn = get_db_connection()


        user = conn.execute("""
            SELECT *
            FROM users
            WHERE username = ?
        """, (username,)).fetchone()


        conn.close()


        if user and check_password_hash(
            user["password_hash"],
            password
        ):

            session["user_id"] = user["id"]

            session["username"] = user["username"]

            session["role"] = user["role"]


            return redirect("/")


        flash(
            "Invalid username or password.",
            "error"
        )


    return render_template("login.html")


# ==================================================
# LOGOUT
# ==================================================

@app.route("/logout")
def logout():

    session.clear()

    return redirect("/login")


# ==================================================
# DASHBOARD
# ==================================================

@app.route("/")
@login_required
def dashboard():

    conn = get_db_connection()


    incidents = conn.execute(
        "SELECT * FROM incidents ORDER BY id DESC"
    ).fetchall()


    critical_incidents = conn.execute(
        "SELECT COUNT(*) FROM incidents WHERE severity = 'Critical'"
    ).fetchone()[0]


    open_incidents = conn.execute(
        "SELECT COUNT(*) FROM incidents WHERE status != 'Closed'"
    ).fetchone()[0]


    conn.close()


    return render_template(

        "dashboard.html",

        incidents=incidents,

        critical_incidents=critical_incidents,

        open_incidents=open_incidents

    )


# ==================================================
# INCIDENT REPORTING
# ==================================================

@app.route("/report", methods=["GET", "POST"])
@login_required
def report_incident():

    if request.method == "POST":

        incident_type = request.form["incident_type"]

        description = request.form["description"]

        severity = request.form["severity"]

        reported_by = request.form["reported_by"]


        conn = get_db_connection()


        conn.execute("""
            INSERT INTO incidents
            (
                incident_type,
                description,
                severity,
                status,
                reported_by
            )
            VALUES (?, ?, ?, ?, ?)
        """, (

            incident_type,

            description,

            severity,

            "Reported",

            reported_by

        ))


        conn.commit()

        conn.close()


        return redirect("/")


    return render_template("report.html")


# ==================================================
# VIEW INCIDENT
# ==================================================

@app.route("/incident/<int:incident_id>")
@login_required
def view_incident(incident_id):

    conn = get_db_connection()


    incident = conn.execute(
        "SELECT * FROM incidents WHERE id = ?",
        (incident_id,)
    ).fetchone()


    conn.close()


    if incident is None:

        return "Incident not found", 404


    return render_template(
        "incident.html",
        incident=incident
    )


# ==================================================
# UPDATE INCIDENT
# ==================================================

@app.route(
    "/incident/<int:incident_id>/update",
    methods=["POST"]
)
@login_required
def update_incident(incident_id):

    status = request.form["status"]


    conn = get_db_connection()


    conn.execute("""
        UPDATE incidents

        SET status = ?

        WHERE id = ?
    """, (

        status,

        incident_id

    ))


    conn.commit()

    conn.close()


    return redirect(
        f"/incident/{incident_id}"
    )


# ==================================================
# CYBERSECURITY POLICIES
# ==================================================

@app.route("/policies")
@login_required
def policies():

    conn = get_db_connection()


    policies = conn.execute(
        "SELECT * FROM policies ORDER BY id DESC"
    ).fetchall()


    conn.close()


    return render_template(
        "policies.html",
        policies=policies
    )


# ==================================================
# ADD POLICY
# ==================================================

@app.route(
    "/policies/add",
    methods=["GET", "POST"]
)
@login_required
def add_policy():

    if request.method == "POST":

        title = request.form["title"]

        description = request.form["description"]


        conn = get_db_connection()


        conn.execute("""
            INSERT INTO policies
            (
                title,
                description
            )
            VALUES (?, ?)
        """, (

            title,

            description

        ))


        conn.commit()

        conn.close()


        return redirect("/policies")


    return render_template(
        "add_policy.html"
    )


# ==================================================
# DELETE POLICY
# ==================================================

@app.route(
    "/policies/delete/<int:policy_id>"
)
@login_required
def delete_policy(policy_id):

    conn = get_db_connection()


    conn.execute(
        "DELETE FROM policies WHERE id = ?",
        (policy_id,)
    )


    conn.commit()

    conn.close()


    return redirect("/policies")


# ==================================================
# BUSINESS CONTINUITY
# ==================================================

@app.route("/continuity")
@login_required
def continuity():

    conn = get_db_connection()


    continuity_plans = conn.execute(
        "SELECT * FROM continuity ORDER BY id DESC"
    ).fetchall()


    conn.close()


    return render_template(
        "continuity.html",
        continuity_plans=continuity_plans
    )


# ==================================================
# ADD BUSINESS CONTINUITY
# ==================================================

@app.route(
    "/continuity/add",
    methods=["GET", "POST"]
)
@login_required
def add_continuity():

    if request.method == "POST":

        business_function = request.form[
            "business_function"
        ]

        priority = request.form["priority"]

        max_downtime = request.form[
            "max_downtime"
        ]

        recovery_procedure = request.form[
            "recovery_procedure"
        ]


        conn = get_db_connection()


        conn.execute("""
            INSERT INTO continuity
            (
                business_function,
                priority,
                max_downtime,
                recovery_procedure
            )
            VALUES (?, ?, ?, ?)
        """, (

            business_function,

            priority,

            max_downtime,

            recovery_procedure

        ))


        conn.commit()

        conn.close()


        return redirect("/continuity")


    return render_template(
        "add_continuity.html"
    )


# ==================================================
# DELETE BUSINESS CONTINUITY
# ==================================================

@app.route(
    "/continuity/delete/<int:plan_id>"
)
@login_required
def delete_continuity(plan_id):

    conn = get_db_connection()


    conn.execute(
        "DELETE FROM continuity WHERE id = ?",
        (plan_id,)
    )


    conn.commit()

    conn.close()


    return redirect("/continuity")


# ==================================================
# DISASTER RECOVERY
# ==================================================

@app.route("/recovery")
@login_required
def recovery():

    conn = get_db_connection()


    recovery_plans = conn.execute(
        "SELECT * FROM disaster_recovery ORDER BY id DESC"
    ).fetchall()


    conn.close()


    return render_template(
        "recovery.html",
        recovery_plans=recovery_plans
    )


# ==================================================
# ADD DISASTER RECOVERY
# ==================================================

@app.route(
    "/recovery/add",
    methods=["GET", "POST"]
)
@login_required
def add_recovery():

    if request.method == "POST":

        system_name = request.form[
            "system_name"
        ]

        rto = request.form["rto"]

        rpo = request.form["rpo"]

        backup_location = request.form[
            "backup_location"
        ]

        recovery_procedure = request.form[
            "recovery_procedure"
        ]

        recovery_status = request.form[
            "recovery_status"
        ]

        last_tested = request.form[
            "last_tested"
        ]


        conn = get_db_connection()


        conn.execute("""
            INSERT INTO disaster_recovery
            (
                system_name,
                rto,
                rpo,
                backup_location,
                recovery_procedure,
                recovery_status,
                last_tested
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (

            system_name,

            rto,

            rpo,

            backup_location,

            recovery_procedure,

            recovery_status,

            last_tested

        ))


        conn.commit()

        conn.close()


        return redirect("/recovery")


    return render_template(
        "add_recovery.html"
    )


# ==================================================
# DELETE DISASTER RECOVERY
# ==================================================

@app.route(
    "/recovery/delete/<int:recovery_id>"
)
@login_required
def delete_recovery(recovery_id):

    conn = get_db_connection()


    conn.execute(
        "DELETE FROM disaster_recovery WHERE id = ?",
        (recovery_id,)
    )


    conn.commit()

    conn.close()


    return redirect("/recovery")


# ==================================================
# BACKUP MANAGEMENT
# ==================================================

@app.route("/backups")
@login_required
def backups():

    conn = get_db_connection()


    backup_records = conn.execute(
        "SELECT * FROM backups ORDER BY id DESC"
    ).fetchall()


    conn.close()


    return render_template(
        "backups.html",
        backup_records=backup_records
    )


# ==================================================
# ADD BACKUP
# ==================================================

@app.route(
    "/backups/add",
    methods=["GET", "POST"]
)
@login_required
def add_backup():

    if request.method == "POST":

        backup_name = request.form[
            "backup_name"
        ]

        system_name = request.form[
            "system_name"
        ]

        backup_type = request.form[
            "backup_type"
        ]

        backup_location = request.form[
            "backup_location"
        ]

        frequency = request.form[
            "frequency"
        ]

        last_backup = request.form[
            "last_backup"
        ]

        backup_status = request.form[
            "backup_status"
        ]

        restore_test = request.form[
            "restore_test"
        ]


        conn = get_db_connection()


        conn.execute("""
            INSERT INTO backups
            (
                backup_name,
                system_name,
                backup_type,
                backup_location,
                frequency,
                last_backup,
                backup_status,
                restore_test
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (

            backup_name,

            system_name,

            backup_type,

            backup_location,

            frequency,

            last_backup,

            backup_status,

            restore_test

        ))


        conn.commit()

        conn.close()


        return redirect("/backups")


    return render_template(
        "add_backup.html"
    )


# ==================================================
# DELETE BACKUP
# ==================================================

@app.route(
    "/backups/delete/<int:backup_id>"
)
@login_required
def delete_backup(backup_id):

    conn = get_db_connection()


    conn.execute(
        "DELETE FROM backups WHERE id = ?",
        (backup_id,)
    )


    conn.commit()

    conn.close()


    return redirect("/backups")


# ==================================================
# SECURITY REPORTS
# ==================================================

@app.route("/reports")
@login_required
def reports():

    conn = get_db_connection()


    # INCIDENT COUNTS

    total_incidents = conn.execute(
        "SELECT COUNT(*) FROM incidents"
    ).fetchone()[0]


    critical_incidents = conn.execute(
        "SELECT COUNT(*) FROM incidents WHERE severity = 'Critical'"
    ).fetchone()[0]


    high_incidents = conn.execute(
        "SELECT COUNT(*) FROM incidents WHERE severity = 'High'"
    ).fetchone()[0]


    medium_incidents = conn.execute(
        "SELECT COUNT(*) FROM incidents WHERE severity = 'Medium'"
    ).fetchone()[0]


    low_incidents = conn.execute(
        "SELECT COUNT(*) FROM incidents WHERE severity = 'Low'"
    ).fetchone()[0]


    # STATUS COUNTS

    open_incidents = conn.execute("""
        SELECT COUNT(*)
        FROM incidents
        WHERE status != 'Closed'
    """).fetchone()[0]


    resolved_incidents = conn.execute("""
        SELECT COUNT(*)
        FROM incidents
        WHERE status IN ('Resolved', 'Closed')
    """).fetchone()[0]


    # OTHER MODULE COUNTS

    total_policies = conn.execute(
        "SELECT COUNT(*) FROM policies"
    ).fetchone()[0]


    total_continuity = conn.execute(
        "SELECT COUNT(*) FROM continuity"
    ).fetchone()[0]


    total_recovery = conn.execute(
        "SELECT COUNT(*) FROM disaster_recovery"
    ).fetchone()[0]


    total_backups = conn.execute(
        "SELECT COUNT(*) FROM backups"
    ).fetchone()[0]


    failed_backups = conn.execute("""
        SELECT COUNT(*)
        FROM backups
        WHERE backup_status = 'Failed'
    """).fetchone()[0]


    failed_restore_tests = conn.execute("""
        SELECT COUNT(*)
        FROM backups
        WHERE restore_test = 'Failed'
    """).fetchone()[0]


    conn.close()


    # ==================================================
    # RISK CALCULATION
    # ==================================================

    risk_score = 0


    risk_score += critical_incidents * 20

    risk_score += high_incidents * 10

    risk_score += medium_incidents * 5

    risk_score += failed_backups * 10

    risk_score += failed_restore_tests * 10


    if risk_score >= 50:

        risk_level = "High"


    elif risk_score >= 20:

        risk_level = "Medium"


    else:

        risk_level = "Low"


    return render_template(

        "reports.html",

        total_incidents=total_incidents,

        critical_incidents=critical_incidents,

        high_incidents=high_incidents,

        medium_incidents=medium_incidents,

        low_incidents=low_incidents,

        open_incidents=open_incidents,

        resolved_incidents=resolved_incidents,

        total_policies=total_policies,

        total_continuity=total_continuity,

        total_recovery=total_recovery,

        total_backups=total_backups,

        failed_backups=failed_backups,

        failed_restore_tests=failed_restore_tests,

        risk_score=risk_score,

        risk_level=risk_level

    )


# ==================================================
# START APPLICATION
# ==================================================

if __name__ == "__main__":

    init_db()

    create_default_admin()

    app.run(debug=True)