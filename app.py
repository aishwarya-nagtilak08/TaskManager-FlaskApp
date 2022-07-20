from asyncio import Task
from crypt import methods
from email.policy import default
from enum import unique
from importlib.resources import contents
from logging import PlaceHolder
from click import password_option
from flask import Flask, flash, redirect, render_template, request, session, url_for, redirect
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt
from flask_login import (
    UserMixin,
    login_user,
    LoginManager,
    current_user,
    logout_user,
    login_required
)
from flask import Flask, render_template, redirect, request, session
from flask_session import Session
import redis


app = Flask(__name__)

login_manager = LoginManager()
login_manager.init_app(app)

app.config['SECRET_KEY'] = 'secretKey'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test.db'
#managed by redis
#app.config['SESSION_TYPE'] = 'redis'
#app.config['SESSION_PERMANENT'] = False
#app.config['SESSION_USE_SIGNER'] = True
#app.config['SESSION_REDIS'] = redis.from_url('redis://localhost:6379')

app.config['SESSION_TYPE'] = 'sqlalchemy'
db = SQLAlchemy(app)
app.config['SESSION_SQLALCHEMY'] = db

sess = Session(app)

bcrypt = Bcrypt(app)

class User(db.Model,UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), nullable=False, unique=True)
    password = db.Column(db.String(50),nullable=False)
    todo = db.relationship('Todo', backref='user', lazy=True)

class Todo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.String(200), nullable=False)
    completed = db.Column(db.Integer, default=0)
    date_creates = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'),default=0)

    def __repr__(self):
        return '<Task %r>' % self.id

class RegisterForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4,max=10)], render_kw={"placeHolder":"Username"})
    password = StringField(validators=[InputRequired(), Length(min=4,max=10)], render_kw={"placeHolder":"Password"})
    submit = SubmitField('Register')

    def validate_username(self, username):
        existing_user_username = User.query.filter_by(username=username.data).first()
        if existing_user_username:
            raise ValidationError('User Already Exists! Please use different Username')

class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4,max=10)], render_kw={"placeHolder":"Username"})
    password = StringField(validators=[InputRequired(), Length(min=4,max=10)], render_kw={"placeHolder":"Password"})
    submit = SubmitField('Login')


@login_manager.user_loader
def load_user(user_id):
    if user_id is not None:
        return User.query.get(user_id)
    return None

@app.route('/', methods=['POST','GET'])
def home():
    return render_template('home.html')

@app.route('/login', methods=['POST', 'GET'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()

        session['user'] = user.username
        session['user_id'] = user.id
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                return render_template('dashboard.html',form=form)
            else:
                flash("Invalid Username or Password")  
                return redirect('/login')

        else:
            return redirect('/login')

    else:
        return render_template('login.html', form=form)

@app.route("/logout")
@login_required
def logout():
    logout_user()
    session.pop('user', default=None)
    return redirect('/')

@app.route('/register', methods=['POST', 'GET'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(username = form.username.data, password = hashed_password)
        try:
            db.session.add(new_user)
            db.session.commit()
            return redirect('/login')
        except:
            return 'Error in registration'
    else:
        return render_template('register.html', form=form)


@app.route('/insert', methods=['POST','GET'])
@login_required
def insert():
    if request.method == 'POST':
        task_content = request.form['content']
        user_id = session['user_id']
        new_task = Todo(content=task_content,user_id=user_id)
        try:
            db.session.add(new_task)
            db.session.commit()
            return redirect('/insert')
        except:
            return 'Insert Exception'

    else:
        tasks = Todo.query.order_by(Todo.date_creates).all()
        return render_template('index.html', tasks=tasks) 

@app.route('/delete/<int:id>')
@login_required
def delete(id):
    task_to_delete = Todo.query.get_or_404(id)

    try:
        db.session.delete(task_to_delete)
        db.session.commit()
        return redirect('/insert')

    except:
        return 'Delete Exception'

@app.route('/update/<int:id>', methods = ['GET','POST'])
@login_required
def update(id):
    task_to_update = Todo.query.get_or_404(id)
    if request.method == 'POST':
        task_to_update.content = request.form['content']
        try:
            db.session.commit()
            return redirect('/insert')
        except:
            return 'Update Exception'
    else:
        return render_template('update.html', task_to_update=task_to_update)


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=8080, debug=True)
    