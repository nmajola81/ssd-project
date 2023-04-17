'''Module containing WTForm definition classes for the web app

Class list:
LoginForm - Form for user login
RegistrationForm - Form for registration
UpdateDetailsForm - Form for updating a user's details (once logged in)
UpdatePasswordForm - Form for updating a user's password (once logged in)
ReportForm - Form for submitting a vulnerability report
MessageForm - Form for submitting messages pertaining to a specific report
'''

from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField, TextAreaField,EmailField, validators, Form, RadioField, SelectField
from wtforms.validators import Length, Email, EqualTo, ValidationError, InputRequired, Optional


class LoginForm(FlaskForm):
    '''User login form'''
    email = EmailField('Email', validators=[InputRequired(), Email(), Length(max=40)])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=6, max=25)])

    submit = SubmitField('Login')

class RegistrationForm(FlaskForm):
    '''User registration form'''
    first_name = StringField('First name (Optional)', validators=[Length(max=40)], render_kw={'placeholder': 'Enter your first name'})
    surname_prefix = SelectField('Surname prefix (Optional)', choices=[('','Surname prefix (Optional)'),('Mr', 'Mr'), ('Mrs', 'Mrs'), ('Ms', 'Ms'), ('Prof', 'Prof'), ('Dr', 'Dr')], render_kw={'placeholder': 'Enter your surname prefix',"style": "width: auto"}, default='')
    surname = StringField('Surname (Optional)', validators=[Length(max=40)],render_kw={'placeholder': 'Enter your surname'})
    email = EmailField(validators=[InputRequired(), Email(), Length(max=40)], render_kw={'placeholder': 'Email'})
    password = PasswordField(validators=[InputRequired(), Length(min=6, max=25)], render_kw={'placeholder': 'Password'})
    confirm = PasswordField(validators=[InputRequired(),EqualTo('password', message='Passwords must match'), Length(min=6, max=25)], render_kw={'placeholder': 'Confirm Password'})
    phone_number = StringField('Phone number (Optional)', validators=[Optional(), Length(min=6, max=20)], render_kw={'placeholder': 'Enter your mobile/phone number'})
    accept_tos = BooleanField('I accept the Privacy and Cookie policies of this website', validators=[InputRequired()])
    submit = SubmitField('Register')

class UpdateDetailsForm(FlaskForm):
    '''Form to update user details'''
    role = SelectField('Role', choices=[('User','User'),('Admin', 'Admin')], render_kw={'placeholder': '[Role]',"style": "width: auto"}, default='User')
    first_name = StringField('First name (Optional)', validators=[Length(max=40)], render_kw={'placeholder': '[None]'})
    surname_prefix = SelectField('Surname prefix (Optional)', choices=[('','Surname prefix (Optional)'),('Mr', 'Mr'), ('Mrs', 'Mrs'), ('Ms', 'Ms'), ('Prof', 'Prof'), ('Dr', 'Dr')], render_kw={'placeholder': 'Enter your surname prefix',"style": "width: auto"}, default='')
    surname = StringField('Surname (Optional)', validators=[Length(max=40)],render_kw={'placeholder': '[None]'})
    phone_number = StringField('Phone number (Optional)', validators=[Optional(), Length(min=6, max=20)], render_kw={'placeholder': '[None]'})
    update_details = SubmitField('Update Details')
class UpdatePasswordForm(FlaskForm):
    '''Form to update user password'''
    password = PasswordField(validators=[Optional(), InputRequired(), Length(min=6, max=20)], render_kw={'placeholder': '[To change your password, type in a new password here]'})
    confirm = PasswordField(validators=[Optional(), InputRequired(), EqualTo('password', message='Passwords must match')], render_kw={'placeholder': '[Confirm Password IF changing passwords]'})
    update_password = SubmitField('Update Password')


class ReportForm(FlaskForm):
    '''Form for report submission'''
    vuln_types = [('injection', 'Injection'),
                  ('broken_authentication', 'Broken Authentication'),
                  ('sensitive_data_exposure', 'Sensitive Data Exposure'),
                  ('xml_external_entities', 'XML External Entities'),
                  ('security_misconfigurations', 'Security Misconfigurations'),
                  ('cross_site_scripting', 'Cross Site Scripting'),
                  ('broken_access_control', 'Broken Access Control'),
                  ('insecure_deserialisation', 'Insecure Deserialisation'),
                  ('availability', 'Availability'),
                  ('integrity', 'Integrity'),
                  ('confidentiality', 'Confidentiality'),
                  ('other', 'Other')]

    vulnerability = RadioField('Type of Vulnerability', choices=vuln_types, default="injection", validators=[InputRequired()])
    explanation = TextAreaField('Explanation of vulnerability', validators=[InputRequired(), Length(min=5, max=1000)])
    whyreport = TextAreaField('Why are you reporting this vulnerability?', validators=[InputRequired(), Length(min=5, max=1000)])
    domainip = TextAreaField('Domain name or IP address relating to the report', validators=[InputRequired(), Length(min=5, max=100)])
    submit = SubmitField('Submit Form')

class MessageForm(FlaskForm):
    '''Form for submission of messages'''
    message = TextAreaField('Message', validators=[InputRequired(), Length(min=1, max=250)])
    submit = SubmitField('Post')