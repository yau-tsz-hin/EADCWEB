import os
from flask import Flask, render_template, redirect, request, send_file, url_for, flash, jsonify, abort, send_from_directory
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length, EqualTo
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import socket
from flask import Flask, jsonify, Response, stream_with_context
import subprocess
import threading
import psutil  # 安裝 psutil: pip install psutil
import select
from threading import Thread
from queue import Queue



app = Flask(__name__)
app.config['SECRET_KEY'] = 'fdsjhkFByukeafgsdyrdgj'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# 資料庫模型
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(25), unique=True, nullable=False)
    password = db.Column(db.String(256), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# 登入表單
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=25)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8, max=256)])
    submit = SubmitField('Login')

# 註冊表單
class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=25)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8, max=256)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')

# 初始化資料庫
with app.app_context():
    db.create_all()

import ipaddress

## Cloudflare 的 IP 範圍清單
#def load_ips_from_file(file_path="D:/py/dc-web-02/cloudflare_ips.txt"):
##def load_ips_from_file(file_path="/home/andyyau/dc-web/dc-web-02/app2/cloudflare_ips.txt"):
#    """從檔案載入 IP 範圍"""
#    try:
#        with open(file_path, "r") as file:
#            lines = file.readlines()
#        ips = [line.strip() for line in lines if line.strip() and not line.startswith("#")]
#        print(f"成功載入的 IP 範圍: {ips}")
#        return ips
#    except FileNotFoundError:
#        print(f"檔案 {file_path} 不存在，請檢查！")
#        return []
#
#CLOUDFLARE_IPS = load_ips_from_file()
#
#def is_cloudflare_ip(ip):
#    """檢查 IP 是否屬於 Cloudflare 的範圍"""
#    for cidr in CLOUDFLARE_IPS:
#        if ipaddress.ip_address(ip) in ipaddress.ip_network(cidr):
#            return True
#    return False
#
#@app.before_request
#def limit_remote_addr():
#    """限制訪問來源 IP"""
#    if not is_cloudflare_ip(request.remote_addr):
#        abort(403)  # 拒絕訪問

# 首頁
@app.route('/')
def home():
    return render_template('home.html')

@app.route('/IMG_0810.jpg')
def serve_image():
    return send_from_directory('static', 'IMG_0810.jpg')

@app.route('/favicon.ico')
def favicon():
    return send_from_directory('static', 'favicon_1.ico')

@app.route('/qwer.png')
@login_required
def qwer():
    return send_from_directory('static', 'qwer.png')



# 登入頁面
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and check_password_hash(user.password, form.password.data):
            login_user(user)
            flash('Logged in successfully!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password', 'danger')
    return render_template('login.html', form=form)

# 註冊頁面
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        existing_user = User.query.filter_by(username=form.username.data).first()
        if existing_user is None:
            # 在註冊時使用 pbkdf2:sha256 加密
            hashed_password = generate_password_hash(form.password.data, method='pbkdf2:sha256')
            new_user = User(username=form.username.data, password=hashed_password)
            db.session.add(new_user)
            db.session.commit()
            flash('Your account has been created!', 'success')
            return redirect(url_for('login'))
        else:
            flash('Username already exists. Please choose a different one.', 'danger')
    return render_template('register.html', form=form)

# 儀表板頁面
@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')

# 登出
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))

    
@app.route('/instructors')
def instructors ():
    return render_template('instructors.html')

@app.route('/courses')
def courses():
    return render_template('courses.html')

@app.route('/tech')
def tech():
    return render_template('tech.html')

@app.route('/news')
def news():
    return render_template('news.html')

@app.route('/courseDATA')
@login_required
def courseDATA():
    return render_template('courseDATA.html')

@app.route('/userDATA')
@login_required
def userDATA():
    return render_template('userDATA.html')

@app.route('/account')
def account():
    return render_template('404.html')


# 統一404錯誤處理
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

#===========================24個資料庫模型==========================

class Instructor(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    bio = db.Column(db.Text)
    email = db.Column(db.String(120), unique=True)

class Course(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    instructor_id = db.Column(db.Integer, db.ForeignKey('instructor.id'))

class Enrollment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    course_id = db.Column(db.Integer, db.ForeignKey('course.id'))
    enrolled_on = db.Column(db.DateTime)

class News(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    content = db.Column(db.Text)
    published_on = db.Column(db.DateTime)

class Certification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    provider = db.Column(db.String(50))
    url = db.Column(db.String(200))

class Assignment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100))
    course_id = db.Column(db.Integer, db.ForeignKey('course.id'))
    due_date = db.Column(db.DateTime)

class Submission(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    assignment_id = db.Column(db.Integer, db.ForeignKey('assignment.id'))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    submitted_on = db.Column(db.DateTime)
    grade = db.Column(db.Float)

class Forum(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100))
    description = db.Column(db.Text)

class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    forum_id = db.Column(db.Integer, db.ForeignKey('forum.id'))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    content = db.Column(db.Text)
    posted_on = db.Column(db.DateTime)

class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    content = db.Column(db.Text)
    commented_on = db.Column(db.DateTime)

class Resource(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100))
    url = db.Column(db.String(200))
    course_id = db.Column(db.Integer, db.ForeignKey('course.id'))

class Announcement(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100))
    content = db.Column(db.Text)
    created_on = db.Column(db.DateTime)

class Feedback(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    content = db.Column(db.Text)
    created_on = db.Column(db.DateTime)

class TechIntro(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100))
    content = db.Column(db.Text)

class DashboardWidget(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(100))
    path = db.Column(db.String(200))
    uploaded_on = db.Column(db.DateTime)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

class Quiz(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100))
    course_id = db.Column(db.Integer, db.ForeignKey('course.id'))

class Question(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    quiz_id = db.Column(db.Integer, db.ForeignKey('quiz.id'))
    content = db.Column(db.Text)
    answer = db.Column(db.String(200))

class QuizResult(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    quiz_id = db.Column(db.Integer, db.ForeignKey('quiz.id'))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    score = db.Column(db.Float)
    taken_on = db.Column(db.DateTime)

class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    message = db.Column(db.String(200))
    created_on = db.Column(db.DateTime)
    is_read = db.Column(db.Boolean, default=False)

class Tag(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True)

class CourseTag(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    course_id = db.Column(db.Integer, db.ForeignKey('course.id'))
    tag_id = db.Column(db.Integer, db.ForeignKey('tag.id'))