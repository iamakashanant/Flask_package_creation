from flask import render_template, flash, redirect, url_for,request
from flaskapp.forms import RegistrationForm, LoginForm
from flask_bcrypt import Bcrypt
from flaskapp.models import User
from flask_login import login_user


# Imp point to understand when the error is like db not defined and below down we create a db
from flaskapp import app, db  



bcrypt=Bcrypt(app)  



UserData=[ 
		{
			"username":'Akash Anant', 
			'title':'User1',
			'useremail': 'aanant20@gmail.com'
		},
		{
			"username":'Fenil Gandhi',
			'title':'User2',
			'useremail':'fg@gmail.com'
		}
]
# creation of db 

db.create_all()


@app.route('/')
def index():
	return render_template('welcome.html',UserData=UserData)




@app.route('/about')
def about_page():
	return render_template('about.html',UserData=UserData)




@app.route("/register", methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
    	hashed_password=bcrypt.generate_password_hash(form.password.data).decode('utf-8')
    	user=User(username=form.username.data, email=form.email.data,password=hashed_password)
    	db.session.add(user)
    	db.session.commit()
    	flash(f'Your Account has been created! You are now been able to log in', 'success')
    	return redirect(url_for('login'))    
    return render_template('register.html', title='Register', form=form)

		

@app.route('/login',methods=['GET','POST'])
def login():
	form =LoginForm()
	if form.validate_on_submit():
		user=User.query.filter_by(email=form.email.data).first()
		if user and bcrypt.check_password_hash(user.password, form.password.data):
			login_user(user, remember=form.remember.data)
			return redirect(url_for("index"))
		else:
			flash('Login Unsuccessful. Please check email and password','danger')
	return render_template('login.html', title ='Login', form=form)


