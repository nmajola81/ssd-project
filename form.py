import wtforms
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField, TextAreaField,EmailField, validators, Form, RadioField, SelectField
from wtforms.validators import Length, Email, EqualTo, ValidationError, InputRequired, Optional


class LoginForm(FlaskForm):
    email = EmailField('Email', validators=[InputRequired(), Email()])
    password = PasswordField('Password', validators=[InputRequired()])

    submit = SubmitField('Login')

class RegistrationForm(FlaskForm):
    first_name = StringField('First name', validators=[Length(max=40)], render_kw={'placeholder': 'Enter your first name'})
    surname_prefix = SelectField('Surname prefix', choices=[('','[None]'),('Mr', 'Mr'), ('Mrs', 'Mrs'), ('Ms', 'Ms'), ('Prof', 'Prof'), ('Dr', 'Dr')], render_kw={'placeholder': 'Enter your surname prefix',"style": "width: auto"}, default='')
    surname = StringField('Surname', validators=[Length(max=40)],render_kw={'placeholder': 'Enter your surname'})
    email = EmailField(validators=[InputRequired(), Email(), Length(max=40)], render_kw={'placeholder': 'Email'})
    password = PasswordField(validators=[InputRequired(), Length(min=6, max=20)], render_kw={'placeholder': 'Password'})
    confirm = PasswordField(validators=[InputRequired(),EqualTo('password', message='Passwords must match')], render_kw={'placeholder': 'Confirm Password'})
    phone_number = StringField('Phone number', render_kw={'placeholder': 'Enter your mobile/phone number'})
    accept_tos = BooleanField('I accept the terms and conditions', validators=[InputRequired()])
    submit = SubmitField('Register')

class UpdateDetailsForm(FlaskForm):
    first_name = StringField('First name', validators=[Length(max=40)], render_kw={'placeholder': '[None]'})
    surname_prefix = SelectField('Surname prefix', choices=[('','[None]'),('Mr', 'Mr'), ('Mrs', 'Mrs'), ('Ms', 'Ms'), ('Prof', 'Prof'), ('Dr', 'Dr')], render_kw={'placeholder': 'Enter your surname prefix',"style": "width: auto"}, default='')
    surname = StringField('Surname', validators=[Length(max=40)],render_kw={'placeholder': '[None]'})
    phone_number = StringField('Phone number', render_kw={'placeholder': '[None]'})
    update_details = SubmitField('Update Details')
class UpdatePasswordForm(FlaskForm):
    password = PasswordField(validators=[Optional(), InputRequired(), Length(min=6, max=20)], render_kw={'placeholder': '[To change your password, type in a new password here]'})
    confirm = PasswordField(validators=[Optional(), InputRequired(), EqualTo('password', message='Passwords must match')], render_kw={'placeholder': '[Confirm Password IF changing passwords]'})
    update_password = SubmitField('Update Password')


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
    explanation = TextAreaField('Explanation of vulnerability', validators=[InputRequired(), Length(min=1, max=1000)])
    whyreport = TextAreaField('Why are you reporting this vulnerability?', validators=[InputRequired(), Length(min=1, max=1000)])
    domainip = TextAreaField('Domain name or IP address relating to the report', validators=[InputRequired(), Length(min=1, max=100)])
    submit = SubmitField('Submit Form')

class MessageForm(FlaskForm):
    message = TextAreaField('Message', validators=[InputRequired(), Length(min=1, max=250)])
    submit = SubmitField('Post')