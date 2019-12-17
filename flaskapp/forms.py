from  wtforms import StringField , PasswordField , SubmitField, BooleanField  
from wtforms.validators import DataRequired ,Length, Email, EqualTo , ValidationError
from flask_wtf import FlaskForm 
from flaskapp.models import User
import os 



#class
#below is the registration form
class RegistrationForm(FlaskForm):
	#attributes
	username=StringField('UserName', validators=[DataRequired(),Length(min=2, max=20)])
	email=StringField('Email',validators=[DataRequired(),Email()])
	password=StringField('Password',validators=[DataRequired()])	
	confirm_password=StringField('Confirm Password',validators=[DataRequired(),EqualTo('password')])
	submit=SubmitField('Sign Up')

	def validate_username(self,username):
		user= User.query.filter_by(username=username.data).first()
		if user:
			raise ValidationError("That username is taken. Please choose a different one")

	def validate_email(self,email):
		user= User.query.filter_by(email=email.data).first()
		if user:
			raise ValidationError("That email is taken. Please choose a different one")



	# def __repr__

#create a login form 

class LoginForm(FlaskForm):
	#attributes
	# username=StringField('UserName', validators=[DataRequired(),Length(MIN=2, MAX=20)])
	# i want user to login with email
	email=StringField('Email',validators=[DataRequired(),Email()])
	password=StringField('Password',validators=[DataRequired()])	
	# confirm_password=StringField('Confirm Password',validators=[DataRequired(),EqualTo('password')])
	# Also add a remember form 
	remember= BooleanField('Remember Me')
	submit=SubmitField('Login')

	#afterwards we need to set a secret key for our application###
	# which is set above










