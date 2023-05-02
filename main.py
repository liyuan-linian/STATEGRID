from flask import *
from flask import Flask
from flask import render_template
from flask_wtf import FlaskForm
from wtforms import StringField, BooleanField, PasswordField
from wtforms.validators import DataRequired
from werkzeug.security import generate_password_hash
from werkzeug.security import check_password_hash
from flask_login import UserMixin
from flask_wtf.csrf import CSRFProtect
from flask_login import login_user, login_required
from flask_login import LoginManager, current_user
from flask_login import logout_user
from flask_sqlalchemy import SQLAlchemy
import json
import uuid
import os

PROFILE_FILE = "profiles.json"


class LoginForm(FlaskForm):
    # 域初始化时，第一个参数是设置label属性的
    username = StringField('User Name', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember_me = BooleanField('remember me', default=False)


class User(UserMixin):
    def __init__(self, username):
        self.username = username
        self.id = self.get_id()

    @property
    def password(self):
        raise AttributeError('password is not a readable attribute')

    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)
        with open(PROFILE_FILE, 'w+') as f:
            try:
                profiles = json.load(f)
            except ValueError:
                profiles = {}
            profiles[self.username] = [self.password_hash,
                                       self.id]
            f.write(json.dumps(profiles))

    def verify_password(self, password):
        password_hash = self.get_password_hash()
        if password_hash is None:
            return False
        return check_password_hash(self.password_hash, password)

    def get_password_hash(self):
        """try to get password hash from file.

        :return password_hash: if the there is corresponding user in
                the file, return password hash.
                None: if there is no corresponding user, return None.
        """
        try:
            with open(PROFILE_FILE) as f:
                user_profiles = json.load(f)
                user_info = user_profiles.get(self.username, None)
                if user_info is not None:
                    return user_info[0]
        except IOError:
            return None
        except ValueError:
            return None
        return None

    def get_id(self):
        """get user id from profile file, if not exist, it will
        generate a uuid for the user.
        """
        if self.username is not None:
            try:
                with open(PROFILE_FILE) as f:
                    user_profiles = json.load(f)
                    if self.username in user_profiles:
                        return user_profiles[self.username][1]
            except IOError:
                pass
            except ValueError:
                pass
        return str(uuid.uuid4())

    @staticmethod
    def get(user_id):
        """try to return user_id corresponding User object.
        This method is used by load_user callback function
        """
        if not user_id:
            return None
        try:
            with open(PROFILE_FILE) as f:
                user_profiles = json.load(f)
                for user_name, profile in user_profiles.iteritems():
                    if profile[1] == user_id:
                        return User(user_name)
        except:
            return None
        return None


app = Flask(__name__)

app.secret_key = os.urandom(24)
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://root:123456@127.0.0.1:3306/STATEGRID'

login_manager = LoginManager()
login_manager.session_protection = 'strong'
login_manager.login_view = 'login'
login_manager.init_app(app=app)

csrf = CSRFProtect()
db = SQLAlchemy(app)
csrf.init_app(app)


class Dianlu(db.Model):
    __tablename__ = 'dianlu'
    id = db.Column(db.Integer, primary_key=True)
    sub_subject = db.Column(db.String(30))
    content = db.Column(db.TEXT)
    submission_date = db.Column(db.DateTime)

    def __init__(self, id, sub_subject, content, submission_date):
        self.id = id
        self.sub_subject = sub_subject
        self.content = content
        self.submission_date = submission_date


@login_manager.user_loader
def load_user(user_id):
    return User.get(user_id)


@app.route('/', methods=['GET', 'POST'])
def hi():
    return render_template('hi.html')


@app.route('/DianLu', methods=['GET', 'POST'])
def dianlu():
    return render_template('DianLu.html', dianlu=Dianlu.query.all())


@app.route('/Dianji', methods=['GET', 'POST'])
def dianji():
    return render_template('DianJi.html')


@app.route('/Dianfen', methods=['GET', 'POST'])
def dianfen():
    return render_template('DianFen.html')


@app.route('/jibao', methods=['GET', 'POST'])
def jibao():
    return render_template('JiBao.html')


@app.route('/dianlidianzi', methods=['GET', 'POST'])
def dianlidianzi():
    return render_template('DianLi.html')


@app.route('/gaoya', methods=['GET', 'POST'])
def gaoya():
    return render_template('GaoYa.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user_name = request.form.get('username', None)
        password = request.form.get('password', None)
        remember_me = request.form.get('remember_me', False)
        user = User(user_name)
        user.password = '111'
        if user.verify_password(password):
            login_user(user, remember=remember_me)
            return redirect(url_for('hi'))
    return render_template('login.html', title='Sign in', form=form)


if __name__ == '__main__':
    app.run()
