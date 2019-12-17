from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask import Flask
import sqlite3
import os



app = Flask(__name__)

app.config['SECRET_KEY']=os.urandom(12).hex()

basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] ='sqlite:///' + os.path.join(basedir, 'UserDB.sqlite')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS ']=False

# database instance 
db=SQLAlchemy(app)
login_manager=LoginManager(app)

from flaskapp import routes



