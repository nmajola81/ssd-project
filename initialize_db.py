'''Module to initialise the database to default config

Functions:
    construct_report - Builds and returns a Report db object
    construct_message - Builds and returns a Message db object

'''
from flask import Flask
from flask_sqlalchemy import SQLAlchemy

from datetime import datetime, timedelta

from encrypt import encrypt_data_dict

from cryptography.fernet import Fernet

from App import User,Report,Message

from werkzeug.security import generate_password_hash


app = Flask(__name__)  # create an instance of the Flask class

app.config['SECRET_KEY'] = '5c7d9fe414fc668876f91637635567c4'  # set the secret key
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'

db = SQLAlchemy(app)

app.app_context().push()

def construct_report(id,user,vuln,expln,why,domain):
    '''
        Helper function to take in the data of a report, encrypt it and construct a Report object
    Args:
        id: Report identifier
        user: User object of the user who submitted the report
        vuln: Vulnerability category; must be one of (Injection,Broken Authentication,Sensitive Data Exposure,XML External Entities,Security Misconfigurations,Cross Site Scripting,Broken Access Control,Insecure Deserialisation,Availability,Integrity,Confidentiality,Other)
        expln: Explanation of the vulnerability
        why: Description of why reporting it is important
        domain: Domains pertaining to vulnerability

    Returns: Report object

    '''

    #Create report data dict
    data = {
        "vulnerability": vuln,
        "explanation": expln,
        "whyreport": why,
        "domainip": domain
    }

    #Encrypt the dict
    encrypted_data = encrypt_data_dict(data, user.enc_key)

    #Construct the report
    add_report = Report(
        id=id,
        report_content=encrypted_data,
        user_id=user.id,
        date_time=datetime.utcnow(),
        user=user
    )

    return add_report

def construct_message(report, from_user, message):
    '''
    Helper function to take in the data of a report, encrypt it and construct a Report object

    Args:
        report:Report object pertaining to this message
        from_user:User object of the user who is posting this message
        message:Message to be posted

    Returns: Message object

    '''

    # Encrypt the message with the key of the report owner
    encrypted_data = encrypt_data_dict(message, report.user.enc_key)

    #Construct the message
    add_msg = Message(
        message=encrypted_data,
        from_user_id=from_user.id,
        report_id=report.id,
        date_time=datetime.utcnow()
    )

    return add_msg


if __name__ == "__main__":

    #First delete all data items from the db
    db.session.query(Message).delete()
    db.session.query(Report).delete()
    db.session.query(User).delete()
    db.session.commit()


    #Make a list of items to add to the db
    addables = []

    #Create the super admin
    sup_admin = User(
        id=1,
        first_name="Super",
        surname="Admin",
        email="admin@ssdproj.com",
        password=generate_password_hash("admin@1234", 'sha256'),
        role="Admin",
        enc_key=Fernet.generate_key().decode('utf-8')
    )

    addables.append(sup_admin)

    #Create two dummy users
    user = User(
        id=2,
        first_name="User1",
        surname="User1Sur",
        email="user@ssdproj.com",
        password=generate_password_hash("user@1234", 'sha256'),
        role="User",
        enc_key=Fernet.generate_key().decode('utf-8')
    )
    addables.append(user)

    #This is a User that has been elevated to Admin status
    user2 = User(
        id=3,
        first_name="User2",
        surname="User2Sur",
        email="user2@ssdproj.com",
        password=generate_password_hash("user2@1234", 'sha256'),
        role="Admin",
        enc_key=Fernet.generate_key().decode('utf-8')
    )
    addables.append(user2)

    #Make a few dummy reports

    admrep1 = construct_report(id=1,
                               user=sup_admin,
                           vuln="sensitive_data_exposure",
                           expln="Admin Explanation 1",
                           why="Admin The whys 1",
                           domain="Admin Some domains here 1"
                               )

    admrep2 = construct_report(id=2,
                               user=sup_admin,
                           vuln="availability",
                           expln="Admin Explanation 2",
                           why="Admin The whys 2",
                           domain="Admin Some domains here 2"
                               )

    admrep3 = construct_report(id=3,
                               user=sup_admin,
                           vuln="cross_site_scripting",
                           expln="Admin Explanation 3",
                           why="Admin The whys 3",
                           domain="Admin Some domains here 3"
                           )

    user1rep1 = construct_report(id=4,
                               user=user,
                           vuln="xml_external_entities",
                           expln="User 1 Explanation 1",
                           why="User 1 The whys 1",
                           domain="User 1 Some domains here 1"
                           )

    user1rep2 = construct_report(id=5,
                               user=user,
                           vuln="broken_authentication",
                           expln="User 1 Explanation 2",
                           why="User 1 The whys 2",
                           domain="User 1 Some domains here 2"
                           )

    user1rep3 = construct_report(id=6,
                               user=user,
                           vuln="security_misconfigurations",
                           expln="User 1 Explanation 3",
                           why="User 1 The whys 3",
                           domain="User 1 Some domains here 3"
                           )

    user1rep4 = construct_report(id=7,
                               user=user,
                           vuln="other",
                           expln="User 1 Explanation 4",
                           why="User 1 The whys 4",
                           domain="User 1 Some domains here 4"
                           )

    user2rep1 = construct_report(id=8,
                               user=user2,
                           vuln="availability",
                           expln="User 2 Explanation 1",
                           why="User 2 The whys 1",
                           domain="User 2 Some domains here 1"
                           )

    user2rep2 = construct_report(id=9,
                               user=user2,
                           vuln="availability",
                           expln="User 2 Explanation 2",
                           why="User 2 The whys 2",
                           domain="User 2 Some domains here 2"
                           )

    #Make a small subset of messages and add them to the addables list
    addables.append(construct_message(admrep1,sup_admin,"Some message 1"))
    addables.append(construct_message(admrep1,sup_admin,"Some message 2"))
    addables.append(construct_message(admrep1,user2,"Some message 3"))
    addables.append(construct_message(admrep1,sup_admin,"Some message 4"))
    addables.append(construct_message(admrep1, user2, "Some message 5"))


    addables.append(construct_message(user1rep2,user,"User1Rep2 Some message 1"))
    addables.append(construct_message(user1rep2,sup_admin,"User1Rep2 Some message 2"))
    addables.append(construct_message(user1rep2,sup_admin,"User1Rep2 Some message 3"))
    addables.append(construct_message(user1rep2,user,"User1Rep2 Some message 4"))
    addables.append(construct_message(user1rep2,user2,"User1Rep2 Some message 5"))
    addables.append(construct_message(user1rep2, user, "User1Rep2 Some message 6"))

    addables.append(construct_message(user2rep1, sup_admin, "User2Rep1 Some message 1"))
    addables.append(construct_message(user2rep1, user2, "User2Rep1 Some message 2"))
    addables.append(construct_message(user2rep1, user2, "User2Rep1 Some message 3"))
    addables.append(construct_message(user2rep1, sup_admin, "User2Rep1 Some message 4"))
    addables.append(construct_message(user2rep1, sup_admin, "User2Rep1 Some message 5"))
    addables.append(construct_message(user2rep1, user2, "User2Rep1 Some message 6"))

    #Now take each item to be added to the DB and add it in.
    for addable in addables:
        print(type(addable))
        db.session.add(addable)

    db.session.commit()
