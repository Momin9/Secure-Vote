import sqlite3
from datetime import datetime
from functools import wraps

import bcrypt
from flask import render_template, request, redirect, url_for, session, flash

from app import app
from app.models import (
    authenticate_voter, cast_vote, list_candidates,
    add_candidate, tally_votes, log_admin_action,
    validate_otp, save_otp, generate_otp,
    reset_databases, create_election, authenticate_admin,
    delete_candidate, list_elections, get_election_id
)
from app.utils import validate_password, send_email_otp, send_email_voter_id, generate_voter_id


# Decorators

def admin_required(f):
    """Ensure the user is logged in as an admin."""

    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'admin_id' not in session:
            flash('You must log in as an admin.', 'error')
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)

    return decorated_function


def voter_required(f):
    """Ensure the user is logged in as a voter."""

    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'voter_id' not in session:
            flash('Please log in first.', 'error')
            return redirect(url_for('voter_login'))
        return f(*args, **kwargs)

    return decorated_function


# Routes
@app.route('/')
def home():
    return render_template('home.html')


@app.route('/register', methods=['GET', 'POST'])
def voter_register():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if not validate_password(password):
            flash('Password must be at least 8 characters long, with uppercase, lowercase, numbers, and symbols.',
                  'error')
            return redirect(url_for('voter_register'))

        if password != confirm_password:
            flash('Passwords do not match.', 'error')
            return redirect(url_for('voter_register'))

        # Check if email already exists
        conn = sqlite3.connect("voting_system.db")
        cursor = conn.cursor()
        cursor.execute("SELECT email FROM voters WHERE email = ?", (email,))
        existing_email = cursor.fetchone()
        conn.close()

        if existing_email:
            flash('Email already registered. Please use a different email.', 'error')
            return redirect(url_for('voter_register'))

        voter_id = generate_voter_id()
        otp = generate_otp()
        save_otp(voter_id, otp, email)

        send_email_otp(email, "Your Registration OTP", f"Your OTP for registration is: {otp}")

        session.update({'voter_id': voter_id, 'email': email, 'password': password})
        app.logger.info(f"Voter ID {voter_id} initiated registration with email {email}.")
        return redirect(url_for('validate_registration_otp'))

    return render_template('voter_register.html')


@app.route('/register/validate', methods=['GET', 'POST'])
def validate_registration_otp():
    if request.method == 'POST':
        otp = request.form['otp']
        voter_id = session.get('voter_id')

        if not voter_id:
            flash('Session expired. Please register again.', 'error')
            return redirect(url_for('voter_register'))

        if validate_otp(voter_id, otp):
            try:
                # Update password and salt in the database
                email = session.pop('email', None)
                password = session.pop('password', None)
                salt = bcrypt.gensalt()
                hashed_password = bcrypt.hashpw(password.encode(), salt)

                conn = sqlite3.connect("voting_system.db")
                cursor = conn.cursor()
                cursor.execute(
                    """
                    UPDATE voters 
                    SET email = ?, password = ?, salt = ? 
                    WHERE voter_id = ?
                    """,
                    (email, hashed_password, salt, voter_id)
                )
                conn.commit()
                try:
                    # Send email notification
                    send_email_voter_id(email, "Your Voter ID", f"Dear User,\n\nYour registration is complete! Your Voter ID is: {voter_id}.\nPlease keep this ID secure as it will be required for logging in.\n\nThank you!")

                    return redirect(url_for('voter_login'))
                except Exception as e:
                    print(f"Error: {e}")

            except Exception as e:
                print(f"Error: {e}")
                flash('An error occurred. Please try again.', 'error')
                return redirect(url_for('voter_register'))

        else:
            flash('Invalid OTP. Please try again.', 'error')

    return render_template('validate_otp.html', action="complete your registration")


@app.route('/register/resend_otp', methods=['POST'])
def resend_registration_otp():
    voter_id = session.get('voter_id')
    email = session.get('email')

    if voter_id and email:
        otp = generate_otp()
        save_otp(voter_id, otp)

        send_email_otp(email, "Your Registration OTP", f"Your OTP for registration is: {otp}")
        flash('A new OTP has been sent to your email.', 'success')
    else:
        flash('Unable to resend OTP. Please try registering again.', 'error')
        return redirect(url_for('voter_register'))

    return redirect(url_for('validate_registration_otp'))


@app.route('/login', methods=['GET', 'POST'])
def voter_login():
    if request.method == 'POST':
        voter_id = request.form.get('voter_id')
        password = request.form.get('password')

        if not voter_id or not password:
            flash('Voter ID and password are required.', 'error')
            return redirect(url_for('voter_login'))

        if authenticate_voter(voter_id, password):
            return redirect(url_for('voting'))
        else:
            flash('Invalid credentials.', 'error')

    return render_template('voter_login.html')


@app.route('/login/validate', methods=['GET', 'POST'])
def validate_login_otp():
    voter_id = session.get('voter_id')

    if not voter_id:
        flash('Session expired. Please log in again.', 'error')
        return redirect(url_for('voter_login'))

    if request.method == 'POST':
        otp = request.form['otp']

        if validate_otp(voter_id, otp):
            flash('Login successful!', 'success')
            return redirect(url_for('voting'))
        else:
            flash('Invalid OTP. Please try again.', 'error')

    return render_template('validate_otp.html', action="log in")


@app.route('/voting', methods=['GET', 'POST'])
@voter_required
def voting():
    election_id = request.args.get('election_id', type=int)
    candidates = list_candidates(election_id)

    # If no candidates are available, return the voting page with a message
    if not candidates:
        return render_template('voting.html', election_id=election_id, message="No candidates available for this election.")

    # Handle POST request for voting
    if request.method == 'POST':
        candidate_id = request.form['candidate_id']
        voter_id = session.get('voter_id')
        election_id = get_election_id(candidate_id)

        # Attempt to cast the vote
        if cast_vote(voter_id, candidate_id, election_id[0][0]):
            message = "Thank you! Your vote has been accepted."
        else:
            message = "You have already cast your vote."

        # Redirect to display the message and avoid form resubmission
        return render_template('voting.html', candidates=candidates, election_id=election_id, message=message)

    # Render the voting page with candidates
    return render_template('voting.html', candidates=candidates, election_id=election_id)


@app.route('/admin', methods=['GET', 'POST'])
@admin_required
def admin():
    if request.method == 'POST':
        name = request.form['name']
        party = request.form['party']
        election_id = request.form.get('election_id', type=int)

        if not election_id:
            flash('Please select an election to add the candidate.', 'error')
        else:
            add_candidate(name, party, election_id)
            flash(f"Candidate '{name}' added successfully!", 'success')
    elections = list_elections()
    candidates = list_candidates(None)
    return render_template('admin.html', candidates=candidates, elections=elections)


@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        admin_id = request.form['admin_id']
        password = request.form['password']
        if authenticate_admin(admin_id, password):
            session['admin_id'] = admin_id
            return redirect(url_for('admin'))
        else:
            flash('Invalid credentials. Please try again.', 'danger')
    return render_template('admin_login.html')


@app.route('/admin/elections', methods=['GET', 'POST'])
@admin_required
def admin_elections():
    if request.method == 'POST':
        name = request.form['name']
        description = request.form['description']
        start_date = request.form['start_date']
        end_date = request.form['end_date']

        if datetime.strptime(start_date, '%Y-%m-%d') > datetime.strptime(end_date, '%Y-%m-%d'):
            print('Start date cannot be after the end date.', 'error')
            return redirect(url_for('admin_elections'))

        if create_election(name, description, start_date, end_date):
            print(f"Election '{name}' created successfully!", 'success')
            return redirect(url_for('admin'))

    return render_template('admin_elections.html')


@app.route('/admin/delete/<int:candidate_id>', methods=['POST'])
@admin_required
def delete_candidate_route(candidate_id):
    # Retrieve candidate details for logging (optional)
    candidates = list_candidates()
    candidate_details = next((c for c in candidates if c[0] == candidate_id), None)
    if candidate_details:
        name = candidate_details[1]
        party = candidate_details[2]

    delete_candidate(candidate_id)

    return redirect(url_for('admin'))


@app.route('/admin/tally')
@admin_required
def admin_tally():
    vote_tally = tally_votes()
    log_admin_action(session['admin_id'], 'TALLY_VOTES', 'Performed vote tallying.')
    return render_template('tally.html', vote_tally=vote_tally)


@app.route('/admin/reset', methods=['POST'])
@admin_required
def reset_databases_route():
    reset_databases()
    flash('Databases have been reset successfully.', 'success')
    return redirect(url_for('admin'))


@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'success')
    return redirect(url_for('home'))
