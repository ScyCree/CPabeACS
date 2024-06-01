import uuid
from datetime import datetime

from flask_mail import Mail
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import PrimaryKeyConstraint

db = SQLAlchemy()
mail = Mail()


class AttributesMiddle(db.Model):
    __tablename__ = "attributes_middle"
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    attribute_id = db.Column(db.Integer, db.ForeignKey('attributes.id'))
    __table_args__ = (PrimaryKeyConstraint('user_id', 'attribute_id'),)


class AttributesModel(db.Model):
    __tablename__ = "attributes"
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.Text, nullable=False)
    description = db.Column(db.Text,default='')
    create_time = db.Column(db.DateTime, default=datetime.now)
    is_base=db.Column(db.Boolean,default=False)

class FavoritesMiddle(db.Model):
    __tablename__="favorites_middle"
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    resource_id = db.Column(db.CHAR(32), db.ForeignKey('resource.id'))
    __table_args__ = (PrimaryKeyConstraint('user_id', 'resource_id'),)

class ResourceModel(db.Model):
    __tablename__ = "resource"
    id = db.Column(db.CHAR(32), primary_key=True, default=uuid.uuid4().hex)
    name = db.Column(db.String(128), nullable=False)
    upload_time = db.Column(db.DateTime, default=datetime.now)
    file_path = db.Column(db.Text, nullable=False)
    policy = db.Column(db.Text, nullable=False)
    abe_cipher = db.Column(db.LargeBinary, nullable=False)
    description = db.Column(db.Text, default='')
    resource_type = db.Column(db.String(6), nullable=False)
    encrypt_type = db.Column(db.String(5),nullable=False,default='bsw07')
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'))


class UserModel(db.Model):
    __tablename__ = "user"
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(16), nullable=False)
    password = db.Column(db.Text, nullable=False)
    email = db.Column(db.String(32), nullable=False, unique=True)
    join_time = db.Column(db.DateTime, default=datetime.now)
    is_admin = db.Column(db.Boolean,default=False)

    resources = db.relationship(ResourceModel, backref='owner')
    attributes = db.relationship("AttributesModel", secondary="attributes_middle",
                                 primaryjoin=(AttributesMiddle.user_id == id),
                                 secondaryjoin=(AttributesMiddle.attribute_id == AttributesModel.id),
                                 backref=db.backref("users")
                                 )
    favorites = db.relationship("ResourceModel", secondary="favorites_middle",
                                 primaryjoin=(FavoritesMiddle.user_id == id),
                                 secondaryjoin=(FavoritesMiddle.resource_id == ResourceModel.id),
                                 backref=db.backref("favors")
                                 )




class EmailCaptchaModel(db.Model):
    __tablename__ = "email_captcha"
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    email = db.Column(db.String(100), nullable=False)
    captcha = db.Column(db.CHAR(6), nullable=False)


class ABEObjectsModel(db.Model):
    __tablename__ = "ABEObjects"
    name = db.Column(db.String(5), primary_key=True)
    object_bytes = db.Column(db.Text, nullable=False)

