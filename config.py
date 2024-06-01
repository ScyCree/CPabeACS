# 私钥
SECRET_KEY = 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'

# 开启基础属性
USE_BASE=True

# 上传文件大小限制20MB
MAX_CONTENT_LENGTH = 20 * 1024 * 1024

# 数据库的配置信息
HOSTNAME = '127.0.0.1'
PORT = '3306'
DATABASE = 'acsdb'
USERNAME = 'scycree'
PASSWORD = 'CPabe_BSW07'
DB_URI = 'mysql+pymysql://{}:{}@{}:{}/{}?charset=utf8'.format(USERNAME, PASSWORD, HOSTNAME, PORT, DATABASE)
SQLALCHEMY_DATABASE_URI = DB_URI
SQLALCHEMY_TRACK_MODIFICATIONS = False

# 邮箱配置
MAIL_SERVER = "smtp.qq.com"
MAIL_USE_SSL = True
MAIL_PORT = 465
MAIL_USERNAME = "xxxxxxxxxxx@qq.com"
MAIL_PASSWORD = "xxxxxxxxxxxxxxxxx"
MAIL_DEFAULT_SENDER = "xxxxxxxxx@qq.com"
