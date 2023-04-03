import werkzeug.security
from flask import Flask, make_response, request, render_template, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy

from form import LoginForm, RegistrationForm, ReportForm

from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user

from werkzeug.security import check_password_hash, generate_password_hash


app = Flask(__name__) # create an instance of the Flask class

app.config['SECRET_KEY'] = '5c7d9fe414fc668876f91637635567c4' # set the secret key
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'

db = SQLAlchemy(app)

# from classdef import User

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

#Define the routes for the app to display specific pages

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String)
    surname_prefix = db.Column(db.String)
    surname = db.Column(db.String)
    email = db.Column(db.String, unique=True)
    password = db.Column(db.String)
    phone_number = db.Column(db.String)
    role = db.Column(db.String, default=False)
    is_deleted = db.Column(db.Boolean, default=False)


@login_manager.user_loader
def load_user(user_id):
    """Loads user as current_user.

    Args:
        user_id -- id of logged in user.
    """

    return User.query.get(int(user_id))

@app.route("/")
def Index():
    name = "Steve"
    return render_template("index.html", data=name)

@app.route("/register", methods=["GET", "POST"])
def register():

    if (current_user.is_authenticated):
        print("Logged in")
        return redirect(url_for('dashboard'))

    form = RegistrationForm()
    if form.validate_on_submit():
        #access the data from fields in the form like this print(form.email)

        if User.query.filter_by(email=form.email.data).first():
            flash('This email is unavailable. Please use a different email.')
            return redirect('/register')

        add_user = User(
            first_name=form.first_name.data,
            surname_prefix=form.surname_prefix.data,
            surname=form.surname.data,
            email=form.email.data,
            password=generate_password_hash(form.password.data, 'sha256'),
            phone_number=form.phone_number.data,
            role="User",
            is_deleted=0
        )

        db.session.add(add_user)
        db.session.commit()

        flash(f"Account for {form.email.data} successfully created", "success")
        return redirect(url_for('login'))


    return render_template("register.html", form=form)

@app.route("/login", methods=["GET", "POST"])
def login():

    if (current_user.is_authenticated):
        print("Logged in")
        return redirect(url_for('dashboard'))
        # return redirect('/dashboard')

    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()

        if not user or not check_password_hash(user.password,form.password.data):
            flash ("Login failed: Invalid/Unknown login credentials.")
            return redirect('/login')


        login_user(user)
        return redirect(url_for('dashboard'))

    return render_template("login.html", title="Login", form=form)

@app.route('/logout')
def logout():
    logout_user()
    return redirect('/login')

@app.route("/report", methods=["GET", "POST"])
@login_required
def report():
    form = ReportForm()
    if form.validate_on_submit():
        flash("Report Submission Successful")
        return redirect(url_for('dashboard'))
    else:
        return render_template("report.html", title="report", form=form)

@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html")



@app.errorhandler(404) #This creates a customise 404 error page to prevent information leakage
def page_not_found(e):
    return render_template("404.html"), 404

@app.errorhandler(500) #This creates a customise 500 error page to prevent information leakage
def internal_server_error(e):
    return render_template("500.html"), 500



#End of route definitions





if __name__ == "__main__":
    app.run(debug=True)