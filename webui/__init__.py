import random
import string
from functools import wraps
import hashlib
from datetime import datetime

from flask import Blueprint
from flask import abort
from flask import request
from flask import redirect
from flask import render_template
from flask import session
from flask import url_for
from flask import flash
from flask import send_from_directory
from flask import current_app

from models import db
from models import User


def hash_and_salt(password):
    password_hash = hashlib.sha256()
    salt = ''.join(random.choice(string.ascii_letters + string.digits) for i in range(8))
    password_hash.update((salt + request.form['password']).encode())
    return password_hash.hexdigest(), salt


def require_admin(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if 'username' in session and session['username'] == 'admin':
            return func(*args, **kwargs)
        else:
            return redirect(url_for('webui.login'))
    return wrapper


def require_login(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if 'username' in session:
            return func(*args, **kwargs)
        else:
            return redirect(url_for('webui.login'))
    return wrapper



webui = Blueprint('webui', __name__, static_folder='static', static_url_path='/static/webui', template_folder='templates')


@webui.route('/')
@require_login
def index():
    return render_template('index.html')

@webui.route('/admin', methods=['GET', 'POST'])
@require_admin
def admin():
    return render_template('admin.html')

@webui.route('/login', methods=['GET', 'POST'])
def login():
    admin_user = User.query.filter_by(username='admin').first()
    if not admin_user:
        if request.method == 'POST':
            if 'password' in request.form:
                password_hash, salt = hash_and_salt(request.form['password']) 
                new_user = User()
                new_user.username = 'admin'
                new_user.password = password_hash
                new_user.salt = salt
                db.session.add(new_user)
                db.session.commit()
                flash('Password set successfully. Please log in.')
                return redirect(url_for('webui.login'))
        return render_template('create_password.html')
    if request.method == 'POST':
        if request.form['password'] and request.form['username']:
                
                user = User.query.filter_by(username=request.form['username']).first()
                password_hash = hashlib.sha256()
                password_hash.update((user.salt + request.form['password']).encode())
                if user is  not None:
                    if user.password == password_hash.hexdigest():
                        session['username'] = request.form['username']
                        last_login_time =  user.last_login_time
                        last_login_ip = user.last_login_ip
                        user.last_login_time = datetime.now()
                        user.last_login_ip = request.remote_addr
                        db.session.commit()
                        flash('Logged in successfully.') 
                        if last_login_ip:
                            flash('Last login from ' + last_login_ip + ' on ' + last_login_time.strftime("%d/%m/%y %H:%M"))
                        if session['username'] == 'admin':
                            return redirect(url_for('webui.admin'))
                        else:
                            return redirect(url_for('webui.index'))
                    else:
                        flash('Wrong password')
                else:
                    flash('This user is not registered. Contact an administrator !')
    return render_template('login.html')


@webui.route('/passchange', methods=['GET', 'POST'])
@require_login
def change_password():
    if request.method == 'POST':
        if 'password' in request.form:
            admin_user = User.query.filter_by(username=session['username']).first()
            password_hash, salt = hash_and_salt(request.form['password'])
            admin_user.password = password_hash
            admin_user.salt = salt
            db.session.add(admin_user)
            db.session.commit()
            flash('Password reset successfully. Please log in.')
            return redirect(url_for('webui.login'))
    return render_template('create_password.html')

@webui.route('/adduser', methods=['GET', 'POST'])
@require_admin
def add_user():
    if request.method == 'POST':
        if 'password' in request.form and 'username' in request.form:
            print(request.form['password'])
            password_hash, salt = hash_and_salt(request.form['password']) 
            new_user = User()
            new_user.username = request.form['username']
            new_user.password = password_hash
            new_user.salt = salt
            db.session.add(new_user)
            db.session.commit()
            flash('User '+request.form['username']+ ' successfully registered')
            return redirect(url_for('webui.admin'))
    return render_template('create_user.html')


@webui.route('/logout')
def logout():
    session.pop('username', None)
    flash('Logged out successfully.')
    return redirect(url_for('webui.login'))

