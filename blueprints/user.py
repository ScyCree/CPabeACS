from random import choice
from re import match
from string import ascii_letters, digits

from flask import Blueprint, request, render_template, redirect, session, url_for, jsonify
from flask_mail import Message
from werkzeug.security import generate_password_hash, check_password_hash

from forms import SignupForm, LoginForm
from ormModels import db, UserModel, mail, EmailCaptchaModel

bp = Blueprint('user', __name__, url_prefix='/user')


@bp.route('/')
def index():
    return render_template('user.html')


@bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('user/login.html')
    else:
        form = LoginForm(request.form)
        if form.validate():
            email = form.email.data
            password = form.password.data
        else:
            return render_template('user/login.html', show='show', title='登录失败', msg='账号或密码不合规')
        user = UserModel.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            return render_template('middle_page.html', message='登录成功！', url=url_for('index'))
        return render_template('user/login.html', show='show', title='登录失败', msg='账号或密码错误')


@bp.route('/logout')
def logout():
    session['user_id'] = None
    return redirect(url_for('user.login'))


@bp.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'GET':
        return render_template('user/signup.html')
    else:
        form = SignupForm(request.form)
        # code=request.form.get('verifycode')
        if form.validate():
            email = form.email.data
            username = form.username.data
            password = form.password.data
            user = UserModel(email=email, username=username, password=generate_password_hash(password))
            db.session.add(user)
            db.session.commit()
            return render_template('middle_page.html', message='注册成功！请登录。', url=url_for('user.login'))
        return render_template('user/signup.html', show='show', title='注册失败', msg='注册失败，检查信息是否有误')


@bp.route('/sendCode', methods=['POST'])
def sendCode():
    email = request.json.get('email')
    if not match(r"^[a-zA-Z0-9_]{4,20}@(163|126|gmail|qq|outlook)\.com", email):
        return jsonify({"code": 400, "msg": "邮箱不合规"})
    # 邮箱是否注册
    user = UserModel.query.filter_by(email=email).first()
    if user:
        return jsonify({"code": 400, "msg": "邮箱已被注册"})
    captcha = EmailCaptchaModel.query.filter_by(email=email).first()
    if captcha:
        return jsonify({"code": 400, "msg": "验证码已存在"})
    # 生成验证码
    captcha = ''.join([choice(ascii_letters + digits) for i in range(6)])
    message = Message(subject='注册验证码', recipients=[email], body=f'您的验证码是:{captcha}', charset='utf-8')
    mail.send(message)
    email_captcha = EmailCaptchaModel(email=email, captcha=captcha)
    db.session.add(email_captcha)
    db.session.commit()
    return jsonify({"code": 200, "msg": "发送成功"})

@bp.route('/user_list')
def user_list():
    key_word = request.args.get('key_word')
    if key_word:
        users = UserModel.query.filter(UserModel.username.contains(key_word)).all()
    else:
        users=UserModel.query.all()
    return render_template('user/user_list.html', users=users)

@bp.route('/check_user/<int:id>')
def check_user(id):
    user=UserModel.query.get(id)
    if user:
        return render_template('user/profile.html',user=user)
    else:
        return '用户不存在'

