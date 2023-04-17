'''Module for the monolithic app for reporting vulnerabilities
Module contains initialising statements for the app, DB classes and Flask routes

Web app routes:
    "/" -- Default route; either shows the NCSC information page (not logged in) or redirects to the dashboard route (logged in)
    "/register" -- Displays user registration form (not logged in) or redirects to dashboard route (logged in)
    "/login" -- Displays login form (not logged in) or redirects to dashboard route (logged in)
    "/logout" -- Logs the user out
    "/submitreport" -- Receives submitted report data, validates it, and loads it into the database (if valid); redirects to dashboard
    "/dashboard" -- Displays a list of reports submitted by the user (for Users) or all users and associated available actions (for Admins)
    "/listusers/<int:active>" -- Displays a list of users along along with available associated actions
    "/messaging/<int:report_id>" -- Displays a specific report (report_id) and all associated messages
    "/messaging/<int:report_id>/<int:msg_id>" -- Displays a specific report (report_id) and all associated messages, and highlights message msg_id
    "/deletereport/<int:report_id>" -- Receives a submitted request to delete a report and deletes it from the db
    "/account/<string:email>" -- Displays the account page of a user with given email address
    "/deletemessage/<int:msg_id>" -- Receives a submitted request to delete a message and deletes it from the db
    "/editreport/<int:report_id>" -- Displays a form to the user and/or receives a submitted request with updated information for the report and effects the changes to the db
    "/deleteaccount/<string:email>" -- Receives a submitted request to delete a user account and sets all personal information of the user to null in the db and sets a flag "is_deleted" to True
    "/privacy" -- Displays a page with the privacy policy
    "/cookies" -- Displays a page with the cookie policy

Classes:
    User - the user table in the db
    Report - the report table in the db
    Message - the message table in the db
'''

from flask import Flask, request, render_template, redirect, url_for, flash, abort
from flask_sqlalchemy import SQLAlchemy

from form import LoginForm, RegistrationForm, ReportForm, MessageForm, UpdateDetailsForm, UpdatePasswordForm

from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user

from werkzeug.security import check_password_hash, generate_password_hash

from datetime import datetime, timedelta

from encrypt import encrypt_data_dict, decrypt_data

from cryptography.fernet import Fernet

from password_strength import PasswordStats

from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)  # create an instance of the Flask class

app.config['SECRET_KEY'] = '5c7d9fe414fc668876f91637635567c4'  # set the secret key
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=10)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'

#Create the sqlaclchemy db object for interfacing with the db
db = SQLAlchemy(app)

#Create the flask login manager interface and initialise it
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

#This limits the number of requests to the server to prevent brute force and (D)DOS attacks
limiter = Limiter(get_remote_address,
                  app=app,
                  default_limits=["200 per day", "50 per hour"]) # Create an instance of the limiter class. Set default requests limits to mitigate spamming/ DOS attacks


class User(db.Model, UserMixin):
    '''User table in the DB'''
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String)
    surname_prefix = db.Column(db.String)
    surname = db.Column(db.String)
    email = db.Column(db.String, unique=True)
    password = db.Column(db.String)
    phone_number = db.Column(db.String)
    role = db.Column(db.String, default="User")
    is_deleted = db.Column(db.Boolean, default=False)
    enc_key = db.Column(db.String)

    userreports = db.relationship('Report', backref="user", lazy=True)
    usermessages = db.relationship('Message', backref="from_user", lazy=True)


class Report(db.Model, UserMixin):
    '''Report table in the DB'''
    id = db.Column(db.Integer, primary_key=True)
    report_content = db.Column(db.LargeBinary)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    date_time = db.Column(db.DateTime, default=datetime.utcnow)

    reportmessages = db.relationship('Message', backref="report", lazy=True)


class Message(db.Model, UserMixin):
    '''Message table in the DB'''
    id = db.Column(db.Integer, primary_key=True)
    message = db.Column(db.LargeBinary)
    from_user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    report_id = db.Column(db.Integer, db.ForeignKey("report.id"), nullable=False)
    date_time = db.Column(db.DateTime, default=datetime.utcnow)

    messagereports = db.relationship("Report", backref="messages")

    # messagereports = db.relationship('Report', backref="messages", lazy=True)


@login_manager.user_loader
def load_user(user_id):
    """Loads user as current_user

    Args:
        user_id -- id of the user logged in
    """

    return User.query.get(int(user_id))


@app.route("/")
def index():
    '''Default route; either shows the NCSC information page (not logged in) or redirects to the dashboard route (logged in)'''
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))
    else:
        return render_template("index.html")


@app.route("/register", methods=["GET", "POST"])
@limiter.limit("1/second", override_defaults=False) # Uses default limits plus only allows one request per second
def register():
    '''Displays user registration form (not logged in) or redirects to dashboard route (logged in)'''
    if (current_user.is_authenticated):
        return redirect(url_for('dashboard'))

    #Obtain the RegistrationForm object
    form = RegistrationForm()

    #Use PasswordStats to determine the strength of the password entered
    stats = PasswordStats(form.password.data)

    #Assume that the password is not weak unless determined otherwise
    weakpass = False
    if stats.strength() < 0.5:
        weakpass = True


    if form.is_submitted() and (not form.validate() or weakpass):
        if weakpass:
            form.password.errors.append(
            "Password not strong enough. Avoid consecutive characters and easily guessed words.")

        flash("Please fix the errors below and try again.", "danger")

    elif form.validate_on_submit():

        #Check if the email used is already taken
        existing_email_user = User.query.filter_by(email=form.email.data).first()

        #If already taken, display error, otherwise, process the info and populate into existing user in the DB
        if existing_email_user:
            if not existing_email_user.is_deleted:
                form.email.errors.append('Email %s is unavailable. Choose another.' % form.email.data)
                form.email.data = ""
                return render_template("register.html", form=form)
            else:

                #Update the user object with the form data
                form.populate_obj(existing_email_user)
                #Re-encrypt password
                existing_email_user.password = generate_password_hash(form.password.data, 'sha256')
                #This user may have been deleted before; if so activate it
                existing_email_user.is_deleted = False
                #Reset to a User; admin will need to grant Admin rights again
                existing_email_user.role = "User"
                db.session.commit()

        else: #If this is a new user and everything checks out

            #Generate a new key
            user_enc_key = Fernet.generate_key()

            #Create the user and add to the DB
            add_user = User(
                first_name=form.first_name.data,
                surname_prefix=form.surname_prefix.data,
                surname=form.surname.data,
                email=form.email.data,
                password=generate_password_hash(form.password.data, 'sha256'),
                phone_number=form.phone_number.data,
                role="User",
                is_deleted=0,
                enc_key=user_enc_key.decode('utf-8')
            )

            db.session.add(add_user)
            db.session.commit()

        flash(f"Account for {form.email.data} successfully created", "success")
        return redirect(url_for('login'))

    return render_template("register.html", form=form)


@app.route("/login", methods=["GET", "POST"])
# @limiter.limit("1/second", override_defaults=False) # Uses default limits plus only allows one request per second
def login():
    '''Displays login form (not logged in) or redirects to dashboard route (logged in)'''
    if (current_user.is_authenticated):
        return redirect(url_for('dashboard'))

    #Obtain the LoginForm object
    #If it has been submitted but doesn't validate correctly, display errors
    #Otherwise check if the user credentials are valid and log the user in
    form = LoginForm()
    if form.is_submitted() and not form.validate():
        flash("Please fix the errors below and try again.", "danger")

    elif form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()

        if not user or not check_password_hash(user.password, form.password.data) or user.is_deleted == True:
            flash("Login failed: Invalid/Unknown login credentials.", "danger")
            return redirect(url_for('login'))

        login_user(user)
        return redirect(url_for('dashboard'))

    return render_template("login.html", title="Login", form=form)


@app.route('/logout')
def logout():
    '''Logs the user out'''
    logout_user()
    return redirect(url_for('login'))


@app.route("/submitreport", methods=["GET", "POST"])
@login_required
def submitreport():
    '''Receives submitted report data, validates it, and loads it into the database (if valid); redirects to dashboard'''

    #Obtain the ReportForm object
    form = ReportForm()

    if form.is_submitted() and not form.validate():
        flash("Please fix the errors below and try again.", "danger")

    elif form.validate_on_submit():

        #Build a dict with all of the report contents
        data = {
            "vulnerability": form.vulnerability.data,
            "explanation": form.explanation.data,
            "whyreport": form.whyreport.data,
            "domainip": form.domainip.data
        }

        #Encrypt it
        encrypted_data = encrypt_data_dict(data, current_user.enc_key)

        #Build the report using the encrypted data
        add_report = Report(
            report_content=encrypted_data,
            user_id=current_user.id,
            date_time=datetime.utcnow()
        )

        #Add it to the DB
        db.session.add(add_report)
        db.session.commit()

        flash("Report Submission Successful", "success")
        return redirect(url_for('dashboard'))
    else:
        return render_template("report.html", title="Create CVD Report", form=form, mode="Create")


@app.route("/dashboard")
@login_required
def dashboard():
    '''Displays a list of reports submitted by the user (for Users) or all users and associated available actions (for Admins)'''

    if current_user.role == "Admin":

        #For Admin users, get all reports (with most recent first)
        reports_encr = db.session.query(Report) \
            .order_by(Report.date_time.desc()).all()

    else:

        #For normal Users, only get reports belonging to that user (with most recent first)
        reports_encr = db.session.query(Report) \
            .where(current_user.id == Report.user_id) \
            .order_by(Report.date_time.desc()).all()

    #Take each report retrieved, decrypt it to be displayed
    reports = []
    for rep in reports_encr:
        content = decrypt_data(rep.report_content, rep.user.enc_key)
        content['vulnerability'] = " ".join(map(str.capitalize, content['vulnerability'].split("_")))
        other_fields = {
            "id": rep.id,
            "user_id": rep.user_id,
            "date_time": rep.date_time.strftime('%Y-%m-%d %H:%M'),
            "user_email": rep.user.email
        }
        other_fields.update(content)
        reports.append(other_fields)

    return render_template("dashboard.html", reports=reports, role=current_user.role)


@app.route("/listusers/<int:active>")
@login_required
def allusers(active):
    '''Displays a list of users along with available associated actions

    Args:
        active -- active==1 means display active users i.e. is_deleted==False; active==0 means displays deleted users i.e. is_deleted==True
    '''
    #Deny non-admin users
    if current_user.role != "Admin":
        abort(403)

    if active == 1:
        users = db.session.query(User) \
            .where(User.is_deleted==False) \
            .order_by(User.id.asc()).all()
    elif active == 0:
        users = db.session.query(User) \
            .where(User.is_deleted==True) \
            .order_by(User.id.asc()).all()

    return render_template("listusers.html", users=users, active=active)


@app.route("/messaging/<int:report_id>/<int:msg_id>", methods=["GET", "POST"])
@app.route("/messaging/<int:report_id>", methods=["GET", "POST"])
@login_required
def messaging(report_id, msg_id=None):
    '''Displays a specific report (report_id) and all associated messages, and highlights message msg_id

    Args:
        report_id -- identifier of the report to display
        msg_id (optional) -- identifier of the message to highlight

    '''
    report_encr = db.session.query(Report) \
        .where(report_id == Report.id) \
        .first()

    #If the report doesn't exist, 404 error
    if not report_encr:
        return abort(404)

    # If the user isn't an admin and they aren't the one who submitted the report, deny
    if current_user.role != "Admin" and report_encr.user_id != current_user.id:
        return abort(403)

    # Get the msg_id anchor if one is present, which will point to a specific message
    anchor = None
    if msg_id:
        anchor = "#msg_%s" % msg_id

    #Decrypt the report data ahead of display
    content = decrypt_data(report_encr.report_content, report_encr.user.enc_key)
    content['vulnerability'] = " ".join(map(str.capitalize, content['vulnerability'].split("_")))
    report = {
        "id": report_encr.id,
        "user_id": report_encr.user_id,
        "user_email": report_encr.user.email,
        "date_time": report_encr.date_time.strftime('%Y-%m-%d %H:%M'),
        "user_is_deleted": report_encr.user.is_deleted
    }
    report.update(content)

    #Obtain the MessageForm (to check if a message may have been posted)
    form = MessageForm()
    if form.is_submitted() and not form.validate():
        flash("Invalid message: unable to post message.", "danger")

    elif form.validate_on_submit():

        #If the message is valid, encrypt it and store in DB
        encrypted_data = encrypt_data_dict(form.message.data, report_encr.user.enc_key)

        add_msg = Message(
            message=encrypted_data,
            from_user_id=current_user.id,
            report_id=report_id,
            date_time=datetime.utcnow()
        )

        db.session.add(add_msg)
        db.session.commit()

        flash("Message posted successfully", 'success')
        # Redirecting back to the same page to get a fresh copy of the page; if user refreshes it won't keep posting the same message over and over again
        return redirect(url_for("messaging", report_id=report_id, msg_id=msg_id))

    # Now retrieving, decrypting and preparing messages for display

    msgs_encr = db.session.query(Message).where(report_id == Message.report_id) \
        .order_by(Message.id) \
        .all()

    msgs = []
    for msg_encr in msgs_encr:

        email_class = "bg-warning"
        if msg_encr.from_user.email == report_encr.user.email:
            email_class = "bg-primary"

        msg = {
            'message': decrypt_data(msg_encr.message, report_encr.user.enc_key),
            'id': msg_encr.id,
            # 'from_user_id': msg_encr.from_user_id,
            'from_user_email': msg_encr.from_user.email,
            'date_time': msg_encr.date_time,
            'email_class': email_class
        }
        msgs.append(msg)

    return render_template("messaging.html", report=report, form=form, msgs=msgs, anchor=anchor)


@app.route("/deletereport/<int:report_id>", methods=["POST"])
@login_required
def deletereport(report_id):
    '''Receives a submitted request to delete a report and deletes it from the db

        Args:
            report_id -- identifier of the report to display
    '''

    #If not an admin user, deny
    if current_user.role != "Admin":
        return abort(403)

    #Get the report with report_id or throw a 404 error
    report = Report.query.filter_by(id=report_id).first_or_404()

    #First delete all messages that are associated with this report (otherwise a foreign key violation will occur and block the action)
    Message.query.filter_by(report_id=report_id).delete()

    #Delete the report
    db.session.delete(report)

    db.session.commit()

    flash("Report successfully deleted", "success")

    return redirect(url_for("dashboard"))


@app.route("/account/<string:email>", methods=["GET", "POST"])
@login_required
def getaccount(email):
    '''Displays the account page of a user with given email address

    Args:
        email: The email address of the user to display
    '''

    # If the user is not an admin and is trying to access someone else's account, deny
    if current_user.email != email and current_user.role != "Admin":
        abort(403)

    #Get the user or if non-existent, throw 404 error
    user = User.query.filter_by(email=email).first_or_404()

    #Get all reports pertaining to this user

    user_reports_encr = db.session.query(Report) \
        .where(user.id == Report.user_id) \
        .all()

    user_reports = []

    #Decrypt and ready all reports ahead of display
    for report_encr in user_reports_encr:
        content = decrypt_data(report_encr.report_content, report_encr.user.enc_key)
        content['vulnerability'] = " ".join(map(str.capitalize, content['vulnerability'].split("_")))
        report = {
            "id": report_encr.id,
            "user_id": report_encr.user_id,
            "user_email": report_encr.user.email,
            "date_time": report_encr.date_time.strftime('%Y-%m-%d at %Hh%M'),
            "vulnerability": content['vulnerability']
        }
        user_reports.append(report)


    #Get all messages pertaining to this user
    msgs_encr = db.session.query(Message).where(user.id == Message.from_user_id) \
        .order_by(Message.id) \
        .all()

    msgs = []
    #Decrypt and ready all messages ahead of display
    for msg_encr in msgs_encr:
        msg = {
            'id': msg_encr.id,
            'from_report_id': msg_encr.report.id,
            'message': decrypt_data(msg_encr.message, msg_encr.report.user.enc_key),
            'from_user_email': msg_encr.from_user.email,
            'date_time': msg_encr.date_time.strftime("%Y-%m-%d at %Hh%M")
        }
        msgs.append(msg)

    #Get the two forms
    update_details_form = UpdateDetailsForm()
    update_password_form = UpdatePasswordForm()

    #First deal with case where Update Details submit button was pressed
    #Validate and do checks
    if 'update_details' in request.form and update_details_form.is_submitted() and not update_details_form.validate():
        flash("Please fix the errors below and try again.", "danger")

    elif 'update_details' in request.form and update_details_form.validate_on_submit():

        #Only the main admin can edit the main admin's details
        #If any user other than user.id 1 is trying to edit that user, deny
        if user.id == 1 and current_user.id != 1:
            abort(403)

        #Obtain updated info
        user.first_name = update_details_form.first_name.data
        user.surname_prefix = update_details_form.surname_prefix.data
        user.surname = update_details_form.surname.data
        user.phone_number = update_details_form.phone_number.data

        # Only update the role of users other than the main admin and only if an admin is logged in
        if user.id != 1 and current_user.role == "Admin":
            user.role = update_details_form.role.data

        db.session.commit()
        flash("Account details have been successfully updated", "success")
        return redirect(url_for("getaccount", email=email))

    elif request.method == 'GET':
        #Otherwise just set the form data to the data in the DB for display purposes
        update_details_form.first_name.data = user.first_name
        update_details_form.surname_prefix.data = user.surname_prefix
        update_details_form.surname.data = user.surname
        update_details_form.phone_number.data = user.phone_number
        update_details_form.role.data = user.role

    #Generate PasswordStats on the password potentially submitted
    stats = PasswordStats(update_password_form.password.data)

    #Assume the pass is not weak and set to weak if it is
    weakpass = False
    if stats.strength() < 0.5:
        weakpass = True

    #Deal with case where Update Password submit button was pressed
    #Validate and do checks
    if 'update_password' in request.form and update_password_form.is_submitted() and (not update_password_form.validate() or weakpass):
        if weakpass:
            update_password_form.password.errors.append(
            "Password not strong enough. Avoid consecutive characters and easily guessed words.")

        flash("Please fix the errors below and try again.", "danger")

    elif update_password_form.validate_on_submit() and 'update_password' in request.form:

        #If the user is active and this isn't a case of an update attempted on the super admin's password by any other user, do the update
        #Otherwise, deny
        if not user.is_deleted and not (user.id == 1 and current_user.id != 1):
            user.password = generate_password_hash(update_password_form.password.data, 'sha256')
            db.session.commit()
            flash("Password has been successfully updated", "success")
        else:
            abort(403)

    return render_template("account.html", user=user, reports=user_reports, msgs=msgs, form_details=update_details_form,
                           form_password=update_password_form)


@app.route("/deletemessage/<int:msg_id>", methods=["POST"])
@login_required
def deletemessage(msg_id):
    '''Receives a submitted request to delete a message and deletes it from the db

    Args:
        msg_id: identifier of message to delete

    '''

    #Get the message to be deleted or if non-existent throw 404 error
    msg_encr = Message.query.filter_by(id=msg_id).first_or_404()

    # If the user isn't an admin and they aren't the one who submitted the report, deny
    if current_user.role != "Admin" and current_user.id != msg_encr.from_user.id:
        return abort(403)

    #Delete it
    msg_report_id = msg_encr.report.id

    db.session.delete(msg_encr)
    db.session.commit()

    flash("Message has been deleted", "success")

    return redirect(url_for("messaging", report_id=msg_report_id))


@app.route("/editreport/<int:report_id>", methods=["GET", "POST"])
@login_required
def editreport(report_id):
    '''Displays a form to the user and/or receives a submitted request with updated information for the report and effects the changes to the db

    Args:
        report_id: identifier of the report to be edited

    '''

    #Get the report to be edited
    report_encr = db.session.query(Report) \
        .where(report_id == Report.id) \
        .first()

    #If it doesn't exist, throw 404 error
    if not report_encr:
        return abort(404)

    # If the user isn't an admin and they aren't the one who submitted the report, deny
    if current_user.role != "Admin" and report_encr.user_id != current_user.id:
        return abort(403)

    #Get the form
    form = ReportForm()

    #If the submit button on the form was pressed
    #Validate and do checks
    if form.is_submitted() and not form.validate():
        flash("Please fix the errors below and try again.", "danger")

    elif form.validate_on_submit():

        #Obtain the updated info from the form

        data = {
            "vulnerability": form.vulnerability.data,
            "explanation": form.explanation.data,
            "whyreport": form.whyreport.data,
            "domainip": form.domainip.data
        }

        #Encrypt the data
        encrypted_data = encrypt_data_dict(data, report_encr.user.enc_key)

        #Update the report contents
        report_encr.report_content = encrypted_data
        db.session.commit()
        flash("The report has been successfully updated.", "success")

        return redirect(url_for('dashboard'))

    #If the submit button was not pressed, set the form fields to the info from the DB for display purposes
    if not form.is_submitted():
        content = decrypt_data(report_encr.report_content, report_encr.user.enc_key)
        form.vulnerability.data = content['vulnerability']
        form.explanation.data = content['explanation']
        form.whyreport.data = content['whyreport']
        form.domainip.data = content['domainip']

    form.submit.label.text = "Update"

    return render_template("report.html", title="Edit CVD Report", form=form, mode="Edit")


@app.route("/deleteaccount/<string:email>", methods=["POST"])
@login_required
def deleteaccount(email):
    '''Receives a submitted request to delete a user account and sets all personal information of the user to null in the db and sets a flag "is_deleted" to True

    Args:
        email:email address of user to be deleted

    '''

    #Get the user or throw 404 error if non-existent
    user = User.query.filter_by(email=email).first_or_404()

    # If the user is not an admin and not the owner of the account OR if the user being deleted is the main admin user, block
    if (current_user.role != "Admin" and current_user.email != email) or (user.id == 1):
        return abort(403)

    # Clear user's personal info and set flag is_deleted to True
    user.surname = ""
    user.first_name = ""
    user.surname_prefix = ""
    user.phone_number = ""
    user.is_deleted = True

    #The code below can be uncommented if it's decided that deleting a user should also delete that user's messages and reports
    # user_reports = Report.query.filter_by(user_id=user.id).all()

    # for user_report in user_reports:
    #     Message.query.filter_by(report_id=user_report.id).delete()

    # db.session.delete(user_reports)
    db.session.commit()

    flash("User account has been deleted", "success")

    #If the account deleted was that of the current user, logout and head to the index route
    if current_user.email == email:
        logout_user()
        return redirect(url_for("index"))
    else:
        #Otherwise figure out if the deletion was done via the user account page or the users list, and then head back to that page
        referrer = request.referrer

        if referrer.find("/account") >= 0:
            return redirect(url_for("getaccount", email=email))
        else:
            return redirect(url_for("allusers",active=1))


@app.route("/privacy")
def privacy():
    '''
        Displays a page with the privacy policy
    '''
    return render_template("privacy.html")

@app.route("/cookies")
def cookies():
    '''
        Displays a page with the cookie policy
    '''
    return render_template("cookies.html")

@app.errorhandler(405)  # This creates a customise 405 error page to prevent information leakage
def page_not_found(e):
    '''Error handler route for 405 errors'''
    return render_template("error.html"), 405


@app.errorhandler(404)  # This creates a customise 404 error page to prevent information leakage
def page_not_found(e):
    '''Error handler route for 404 errors'''
    return render_template("error.html"), 404


@app.errorhandler(403)  # This creates a customise 403 error page to prevent information leakage
def internal_server_error(e):
    '''Error handler route for 403 errors'''
    return render_template("error.html"), 403


@app.errorhandler(500)  # This creates a customise 500 error page to prevent information leakage
def internal_server_error(e):
    '''Error handler route for 500 errors'''
    return render_template("error.html"), 500


# End of route definitions


if __name__ == "__main__":
    app.run(debug=True)


#  import pyotp
#  def OTP(): #The OTP function is responsible for providing a secondary form of authentication for the user, in this case, the user will receive a passcode, which they will need to repeat
#    totp = pyotp.TOTP('base32secret3232')
#    print("This is your one-time passcode: ")
#    print(totp.now())
#    userOTP = input("Please provided your passcode: ")
#    otpass = totp.verify(userOTP)
#    if otpass == True: #If the passcode is correct, you now have access to the rest of the application
#        print("You are now logged in")
#        return True
#    else:
#        print("Access Forbidden") #If the passcode is incorrect, the program terminates (multiple retries are not recommended for OTP)
#        return False