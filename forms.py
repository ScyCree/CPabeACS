import wtforms
from wtforms.validators import Email, Length

from ormModels import UserModel, EmailCaptchaModel


class LoginForm(wtforms.Form):
    # 验证格式
    email = wtforms.StringField(validators=[Email(message="邮箱格式错误！")])
    password = wtforms.StringField(validators=[Length(min=6, max=20, message="密码格式错误！")])


class SignupForm(wtforms.Form):
    # 验证格式
    email = wtforms.StringField(validators=[Email(message="邮箱格式错误！")])
    captcha = wtforms.StringField(validators=[Length(min=6, max=6, message="验证码格式错误！")])
    username = wtforms.StringField(validators=[Length(min=3, max=16, message="用户名格式错误！")])
    password = wtforms.StringField(validators=[Length(min=6, max=20, message="密码格式错误！")])

    # 邮箱是否被注册？
    def validate_email(self, field):
        email = field.data
        user = UserModel.query.filter_by(email=email).first()
        if user:
            raise wtforms.ValidationError(message="该邮箱已经被注册！")

    # 验证码是否正确？
    def validate_captcha(self, field):
        captcha = field.data
        email = self.email.data
        captcha_model = EmailCaptchaModel.query.filter_by(email=email, captcha=captcha).first()
        if not captcha_model:
            raise wtforms.ValidationError(message='验证码错误！')


class UserInfoForm(wtforms.Form):
    username = wtforms.StringField(validators=[Length(min=3, max=16, message="用户名格式错误！")])
    email = wtforms.StringField(validators=[Email(message="邮箱格式错误！")])
