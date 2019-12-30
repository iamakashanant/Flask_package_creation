from flask import render_template, flash, redirect, url_for,request,g , jsonify
from flaskapp.forms import RegistrationForm, LoginForm, ForgotPasswordForm, ResetPasswordForm, EditProfileForm
from datetime import datetime, timedelta
from flask_mail import Mail, Message
from flask_login import login_user
from flaskapp.models import User
from flask_bcrypt import Bcrypt
import secrets, string
import uuid
import logging
# Imp point to understand when the error is like db not defined and below down we create a db
from flaskapp import app, db 


from flask_login import current_user, login_user


bcrypt=Bcrypt(app)  

logger = logging.getLogger(__name__)


app.config.update(dict(
    DEBUG = True,
    MAIL_SERVER = 'smtp.gmail.com',
    MAIL_PORT = 587,
    MAIL_USE_TLS = True,
    MAIL_USE_SSL = False,
    MAIL_USERNAME = 'aanant20@gmail.com',
    MAIL_PASSWORD = 'TOBIN@2711',
))
mail = Mail(app)
mail.init_app(app)

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



@app.route('/edit_profile', methods=['GET', 'POST'])
def account():
	

	user_name=User.query.filter_by(username=current_user.username).first()
	user=User.query.get(user_name.id)
	form = EditProfileForm(obj=user)
	






	return render_template('edit_profile.html', form=form)



def save_picture(form_picture):
    random_hex = secrets.token_hex(8)
    _, f_ext = os.path.splitext(form_picture.filename)
    picture_fn = random_hex + f_ext
    picture_path = os.path.join(app.root_path, 'static/profile_pics', picture_fn)

    output_size = (125, 125)
    i = Image.open(form_picture)
    i.thumbnail(output_size)
    i.save(picture_path)

    return picture_fn









	



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
			return redirect(url_for("account"))
		else:
			flash('Login Unsuccessful. Please check email and password','danger')
	return render_template('login.html', title ='Login', form=form)



@app.route('/forgot_password',methods=["GET","POST"])
def forgot_password():
	form=ForgotPasswordForm()
	
	if request.method=='GET':
		return render_template('forgot_password.html', form=form)
	
	elif request.method=='POST':
		
		if form.validate_on_submit():
			user_name=User.query.filter_by(username=form.username.data).first() or None
			
			if user_name is None:
				return jsonify({"status": "error", 'error_message': 'User not found1'}), 400
			
			if user_name:
				id=uuid.uuid4().int
				OTP=int(str(id)[:4])
				user_a=db.session.query(User).filter_by(username=user_name.username).first()
				user_a.OTP_over_mail=OTP
				user_a.reset_password_till=datetime.now() + timedelta(days=1)
				db.session.add(user_a)
				db.session.commit()
				# return (user_name.email+"-"+str(OTP))
				subject='OTP for Reset Password'
				msg = Message(subject=subject, sender='aanant20@gmail.com', recipients=[user_name.email])
				msg.body="Your One Time Password is" +" " + str(OTP) + '\n\n' + 'Regards, Site Admin'
				mail.send(msg)
				flash('One Time Password has been sent to your mail')
				return redirect (url_for('reset_password'))

			else:
				return jsonify({"status": "error", 'error_message': 'User not found2'}), 400
			return jsonify({"status": "error", 'error_message': 'Form not valid'}), 400
		return jsonify({"status": "error", 'error_message': 'User not found'}), 40




# @csrf.exempt
@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
	form=ResetPasswordForm()
	
	if request.method=='GET':
		return render_template('reset_password.html', form=form)
	

	elif request.method=='POST':
		data=request.form.to_dict()
		OTP=data.get('otp')

		user_attr=db.session.query(User).filter_by(OTP_over_mail=OTP).first() or None

		if user_attr is None:
			return jsonify({"error_message": "OTP is invalid"}), 400

		if user_attr.reset_password_till <  datetime.now():
			return jsonify({"error_message": "OTP has expired. Try again"}), 400

		user = db.session.query(User).filter_by(id=user_attr.id).first() or None
		if user is None:
			return jsonify({"error_message": "User not found"}), 400


		password = data.get('password')
		if not all([type(password) == str,  4 <= len(password) <= 20]):
			return jsonify({"error_message": "Password should be between 4 to 20 characters"}), 400


		try:
			user.password = bcrypt.generate_password_hash(password)
			db.session.add(user)
			user_attr.OTP_over_mail = None
			user_attr.reset_password_till = None
			db.session.add(user_attr)
			db.session.commit()

		except Exception as e:
			logging.exception(e)
			return jsonify({"error_message": "Password could not be reset."}), 400
		return redirect(url_for('account'))






    # elif request.method=="POST":
        
    #     data=request.form.to_dict()
    #     OTP=data.get('otp')
    #     return render_template('reset_password.html', form=form)



    #     user_attr_obj=db.session.query(UserAttribute).filter_by(reset_password_token=OTP).first() or None
        
    #     if user_attr_obj is None:
    #         return jsonify({"error_message": "OTP is invalid"}), 400
    #     print(user_attr_obj.reset_password_till)
    #     if user_attr_obj.reset_password_till <  datetime.now():
    #         return jsonify({"error_message": "OTP has expired. Try again"}), 400

    #     user = db.session.query(User).filter_by(id=user_attr_obj.user_id).first() or None
    #     if user is None:
    #         return jsonify({"error_message": "User not found"}), 400


    #     password = data.get('password')
    #     if not all([type(password) == str,  4 <= len(password) <= 20]):
    #         return jsonify({"error_message": "Password should be between 4 to 20 characters"}), 400

    #     try:
    #         user.password = generate_password_hash(password)
    #         db.session.add(user)
    #         user_attr_obj.reset_password_token = None
    #         user_attr_obj.reset_password_till = None
    #         db.session.add(user_attr_obj)
    #         db.session.commit()
        
    #     except Exception as e:
    #         logging.exception(e)
    #         return jsonify({"error_message": "Password could not be reset."}), 400

    #     return jsonify({"success": "Password reset successful"}), 200


			





#  edit the content forgot password email template and Here is your OTP

# create OTP and sent back the mail to user email + redirect to reset passsword and show up the page like PLease enter OTP and button as Reset password 


# @csrf.exempt
# @app.route('/user/reset_password', methods=['GET', 'POST'])
# def reset_password():/
#     # If user is authenticated, redirect to homepage
#     if g.user.is_authenticated:
#         return redirect('/')

#     # Return template pages
#     if request.method == 'GET':
#         if 'success' in request.args:
#             return render_template(reset_password_success_template)

#         token = request.args.get('token')   
#         if bool(token) is False:
#             return redirect(url_for('forgot_password'))

#         return render_template(reset_password_template)

#     # Reset password form, validate form & reset password
#     elif request.method == 'POST':
#         data = request.form.to_dict()
#         token = data.get('token')
#         if bool(token) is False:
#             return jsonify({"error_message": "Token is missing"}), 400

#         password = data.get('password')
#         if bool(password) is False:
#             return jsonify({"error_message": "Password is missing"}), 400

#         user_attr_obj = db.session.query(UserAttribute).filter_by(reset_password_token=token).first() or None
#         if user_attr_obj is None:
#             return jsonify({"error_message": "Token is invalid"}), 400

#         # Validate if token is active
#         if user_attr_obj.reset_password_till < datetime.now():
#             return jsonify({"error_message": "Token has expired. Try again"}), 400

#         user = db.session.query(User).filter_by(id=user_attr_obj.user_id).first() or None
#         if user is None:
#             return jsonify({"error_message": "User not found"}), 400

#         # Validate password according to rules
#         if not all([
#             type(password) == str,  # password should be a string
#             4 <= len(password) <= 20  # password should be between 4 to 20 characters
#         ]):
#             return jsonify({"error_message": "Password should be between 4 to 20 characters"}), 400

#         try:
#             user.password = generate_password_hash(password)
#             db.session.add(user)
#             user_attr_obj.reset_password_token = None
#             user_attr_obj.reset_password_till = None

#             db.session.add(user_attr_obj)

#             db.session.commit()
#         except Exception as e:
#             logging.exception(e)
#             return jsonify({"error_message": "Password could not be reset."}), 400

#         return jsonify({"success": "Password reset successful"}), 200
