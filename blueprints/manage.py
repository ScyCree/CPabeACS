from random import choice
from string import ascii_letters, digits

from charm.core.engine.util import objectToBytes
from cpabe_bsw07 import CPabe_BSW07
from charm.toolbox.pairinggroup import PairingGroup
from flask import Blueprint, render_template, request, g, redirect, url_for, session

from cpabe_rsa24 import CPabe_RSA24
from forms import UserInfoForm
from ormModels import ABEObjectsModel, db, UserModel, AttributesModel, AttributesMiddle, ResourceModel
from sqlalchemy import or_
import json
from os import remove

bp = Blueprint('manage', __name__, url_prefix='/manage')


@bp.before_request
def before_request():
    if g.user and g.user.is_admin == 1:
        pass
    else:
        return '不是管理员'


@bp.route('/')
def index():
    return render_template("manage.html")

@bp.route('/resource')
def resource():
    if request.method == 'GET':
        key_word = request.args.get('key_word')
        if key_word:
            resources = ResourceModel.query.filter(or_(
        ResourceModel.name.contains(key_word),
        ResourceModel.description.contains(key_word)
    )).all()
        else:
            resources = ResourceModel.query.all()
        return render_template('manage/resource.html', resources=resources)

@bp.route('/delete_resource/<string:resource_id>')
def delete_resource(resource_id):
    resource = ResourceModel.query.filter_by(id=resource_id).first()
    if resource:
        encf_path= 'storage/' + resource.id + '.enc'
        remove(encf_path)
        db.session.delete(resource)
        db.session.commit()
        return redirect(url_for('manage.resource'))
    return '资源不可访问'

@bp.route('/attribute')
def attribute():
    attributes = AttributesModel().query.all()
    return render_template("manage/attribute.html", attributes=attributes)


@bp.route('/add_attribute')
def add_attribute():
    name = ''.join([choice(ascii_letters + digits) for i in range(16)])
    attribute = AttributesModel(name=name)
    db.session.add(attribute)
    db.session.commit()
    return redirect(url_for('manage.attribute'))


@bp.route('/delete_attribute/<int:attribute_id>')
def delete_attribute(attribute_id):
    attribute = AttributesModel.query.get(attribute_id)
    db.session.delete(attribute)
    db.session.commit()
    return redirect(url_for('manage.attribute'))


@bp.route('/edit_attribute/<int:attribute_id>', methods=['GET', 'POST'])
def edit_attribute(attribute_id):
    if request.method == 'GET':
        attribute = AttributesModel.query.get(attribute_id)
        return render_template("manage/edit_attribute.html", attribute=attribute)
    else:
        attribute_name = request.form.get('attribute_name').upper()
        description = request.form.get('description').upper()
        attribute = AttributesModel.query.get(attribute_id)
        attribute.name = attribute_name
        attribute.description=description
        db.session.commit()
        return redirect(url_for('manage.attribute'))


@bp.route('/user')
def user():
    users = UserModel.query.all()
    return render_template("manage/user.html", users=users)


@bp.route('/add_user')
def add_user():
    name = ''.join([choice(ascii_letters + digits) for i in range(16)])
    users = UserModel(username=name, password='<PASSWORD>', email=name + '@qwe.qwe')
    db.session.add(users)
    db.session.commit()
    return redirect(url_for('manage.user'))


@bp.route('/delete_user/<int:user_id>')
def delete_user(user_id):
    user = UserModel.query.get(user_id)
    db.session.delete(user)
    db.session.commit()
    return redirect(url_for('manage.user'))


@bp.route('/edit_user/<int:user_id>', methods=['GET', 'POST'])
def edit_user(user_id):
    if request.method == 'GET':
        user = UserModel.query.get(user_id)
        attributes_li = AttributesModel.query.all()
        return render_template("manage/edit_user.html", user=user, attributes_li=attributes_li)
    else:
        form = UserInfoForm(request.form)
        if form.validate():
            username = form.username.data
            email = form.email.data
        else:
            render_template('middle_page.html', message='数据格式错误',
                            url=url_for('manage.edit_user', user_id=user_id))
        attributes = request.form.keys()
        attributes_li = AttributesModel.query.all()
        user = UserModel.query.get(user_id)
        user.username = username
        user.email = email
        vali_attributes = [i.id for i in attributes_li if str(i.id) in attributes]
        cur_attributes = [i.id for i in user.attributes]
        for i in vali_attributes:
            if i not in cur_attributes:
                mid = AttributesMiddle(user_id=user_id, attribute_id=i)
                db.session.add(mid)
            else:
                cur_attributes.remove(i)
        for i in cur_attributes:
            if i not in vali_attributes:
                mid = AttributesMiddle.query.filter_by(user_id=user_id, attribute_id=i)
                mid.delete()
        db.session.commit()
        return redirect(url_for('manage.user'))


@bp.route('/change_user/<int:user_id>')
def change_user(user_id):
    user = UserModel.query.get(user_id)
    if user:
        session['user_id'] = user.id
        return render_template('middle_page.html', message='切换成功！', url=request.referrer)
    return render_template('middle_page.html', message='切换失败！', url=request.referrer)


@bp.route('/system')
def system():
    attributes=AttributesModel.query.all()
    return render_template('manage/system.html',attributes=attributes)


@bp.route('/init_system/<string:enc_type>')
def init_system(enc_type):
    if enc_type=='bsw07':
        pk = ABEObjectsModel.query.filter_by(name='07pk').first()
        if pk:
            return '已初始化，无需重复初始化'
        try:
            # instantiate a bilinear pairing map
            pairing_group = PairingGroup('SS512')
            # CP-ABE under DLIN (2-linear)
            cpabe = CPabe_BSW07(pairing_group)
            # run the set up
            (pk, msk) = cpabe.setup()
            pk_obj_bytes = objectToBytes(pk, pairing_group)
            msk_obj_bytes = objectToBytes(msk, pairing_group)
            pk_model = ABEObjectsModel(name='07pk', object_bytes=pk_obj_bytes)
            msk_model = ABEObjectsModel(name='07msk', object_bytes=msk_obj_bytes)
            db.session.add(pk_model)
            db.session.add(msk_model)
            db.session.commit()
            return '初始化成功'
        except Exception as e:
            return '算法初始化失败，检查charm crypto是否正常安装'
    elif enc_type=='rsa24':
        pk = ABEObjectsModel.query.filter_by(name='24pk').first()
        if pk:
            return '已初始化，无需重复初始化'
        cpabe = CPabe_RSA24()
        (pk, msk) = cpabe.setup()
        pk_obj_bytes = json.dumps(pk)
        msk_obj_bytes = json.dumps(msk)
        pk_model = ABEObjectsModel(name='24pk', object_bytes=pk_obj_bytes)
        msk_model = ABEObjectsModel(name='24msk', object_bytes=msk_obj_bytes)
        db.session.add(pk_model)
        db.session.add(msk_model)
        db.session.commit()
        return '初始化成功'
    else:
        return '不支持的加密方案'

@bp.route('/set_base')
def set_base():
    name=request.args.get('name')
    nbase = AttributesModel.query.filter_by(name=name).first()
    if nbase:
        obase = AttributesModel.query.filter_by(is_base=True).first()
        if obase:
            obase.is_base = False
        nbase.is_base = True

        db.session.commit()
        return redirect(request.referrer)
    else:
        return '属性不存在'
