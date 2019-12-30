from  wtforms import StringField , PasswordField , SubmitField, BooleanField ,TextAreaField
from wtforms.validators import DataRequired ,Length, Email, EqualTo , ValidationError, NumberRange
from flask_wtf.file import FileField, FileAllowed
from flask_wtf import FlaskForm 
from flaskapp.models import User
import os 
from flask_login import current_user
from PIL import Image



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


class ForgotPasswordForm(FlaskForm):
	username=StringField('UserName', validators=[DataRequired(),Length(min=4, max=20)])
	submit=SubmitField('Send me the OTP to reset password')


class ResetPasswordForm(FlaskForm):
	otp=StringField('Enter OTP', validators=[DataRequired(),Length(min=4, max=4)])
	submit=SubmitField('Reset Password')





class EditProfileForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[Length(min=0, max=140)])
    # picture = FileField('Update Profile Picture', validators=[FileAllowed(['jpg', 'png'])])
	submit = SubmitField('Submit')



    # submit = SubmitField('Update')