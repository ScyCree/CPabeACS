from functools import wraps

from flask import g, redirect, url_for


def is_admin(func):
    # 保留func的信息
    @wraps(func)
    def inner(*args, **kwargs):
        if g.user.is_admin:
            return func(*args, **kwargs)
        else:
            return 'access denied'

    return inner


def check_login(func):
    # 保留func的信息
    @wraps(func)
    def inner(*args, **kwargs):
        if g.user:
            return func(*args, **kwargs)
        else:
            return redirect(url_for('user.login'))

    return inner
