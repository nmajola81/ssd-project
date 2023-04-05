import wtforms
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField, TextAreaField,EmailField, validators, Form, RadioField, SelectField
from wtforms.validators import Length, Email, EqualTo, ValidationError, InputRequired
from password_validator import PasswordValidator


class LoginForm(FlaskForm):
    email = EmailField('Email', validators=[InputRequired(), Email()])
    password = PasswordField('Password', validators=[InputRequired()])

    submit = SubmitField('Login')

class RegistrationForm(FlaskForm):
    first_name = StringField('First name', validators=[Length(max=40)], render_kw={'placeholder': 'Enter your first name'})
    surname_prefix = SelectField('Surname prefix', choices=[('','[Select one]'),('Mr', 'Mr.'), ('Mrs', 'Mrs.'), ('Ms', 'Ms.'), ('Prof', 'Prof.'), ('Dr', 'Dr.')], render_kw={'placeholder': 'Enter your surname prefix',"style": "width: auto"})
    surname = StringField('Surname', validators=[Length(max=40)],render_kw={'placeholder': 'Enter your surname'})
    email = EmailField(validators=[InputRequired(), Email(), Length(max=40)], render_kw={'placeholder': 'Email'})
    password = PasswordField(validators=[InputRequired(), Length(min=6, max=20)], render_kw={'placeholder': 'Password'})
    confirm = PasswordField(validators=[InputRequired(),EqualTo('password', message='Passwords must match')], render_kw={'placeholder': 'Confirm Password'})
    phone_number = StringField('Phone number', render_kw={'placeholder': 'Enter your mobile/phone number'})
    accept_tos = BooleanField('I accept the terms and conditions', validators=[InputRequired()])
    submit = SubmitField('Register')

class ReportForm(FlaskForm):
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
    explanation = TextAreaField('Explanation of vulnerability', validators=[InputRequired()])
    whyreport = TextAreaField('Why are you reporting this vulnerability?', validators=[InputRequired()])
    domainip = TextAreaField('Domain name or IP address relating to the report', validators=[InputRequired(), Length(min=1, max=50)])
    submit = SubmitField('Submit Form')

class MessageForm(FlaskForm):
    message = TextAreaField('Message', validators=[InputRequired(), Length(min=1, max=250)])
    submit = SubmitField('Post')