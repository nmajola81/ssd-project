from flask import Flask, make_response, request, render_template, redirect, url_for, flash
from form import LoginForm, RegistrationForm, ReportForm

app = Flask(__name__) # create an instance of the Flask class

app.config['SECRET_KEY'] = '5c7d9fe414fc668876f91637635567c4' # set the secret key
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'


#Define the routes for the app to display specific pages

@app.route("/")
def Index():
    name = "Steve"
    return render_template("index.html", data=name)

@app.route("/register", methods=["GET", "POST"])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        #acces the data from fields in the form like this print(form.email)
        flash("Thank you for registering")
        return redirect(url_for('login'))
    else:
        return render_template("register.html", form=form)

@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        flash("Login Successful")
        return redirect(url_for('Dashboard'))
    else:
        return render_template("login.html", title="Login", form=form)
    
@app.route("/report", methods=["GET", "POST"])
def report():
    form = ReportForm()
    if form.validate_on_submit():
        flash("Report Submission Successful")
        return redirect(url_for('Dashboard'))
    else:
        return render_template("report.html", title="report", form=form)

@app.route("/dashboard")
def Dashboard():
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