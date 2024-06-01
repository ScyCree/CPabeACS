from flask import Flask, session, g, redirect, url_for
from flask_migrate import Migrate

import config
from blueprints.manage import bp as manage_bp
from blueprints.resource import bp as resource_bp
from blueprints.user import bp as user_bp
from decorators import check_login
from ormModels import db, mail, UserModel

app = Flask(__name__)
# 绑定配置文件
app.config.from_object(config)

# 数据库orm模型

# flask db init：只需要执行一次
# flask db migrate：将orm模型生成迁移脚本
# flask db upgrade：将迁移脚本映射到数据库中

db.init_app(app)
mail.init_app(app)
migrate = Migrate(app, db)

app.register_blueprint(user_bp)
app.register_blueprint(manage_bp)
app.register_blueprint(resource_bp)


@app.before_request
def identify():
    user_id = session.get("user_id")
    if user_id:
        user = UserModel.query.get(user_id)
        setattr(g, "user", user)
    else:
        setattr(g, "user", None)


@app.route('/')
@check_login
def index():
    return redirect(url_for('resource.index'))


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=80)
