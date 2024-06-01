import json
import random
from io import BytesIO
from os import remove
from uuid import uuid4

from charm.core.engine.util import objectToBytes, bytesToObject
from charm.toolbox.pairinggroup import PairingGroup, GT
from flask import Blueprint, render_template, request, g, send_file, url_for, redirect, current_app

from aes import encrypt_file, decrypt_file, encrypt_bytes
from cpabe_bsw07 import CPabe_BSW07
from cpabe_rsa24 import CPabe_RSA24
from ormModels import AttributesModel, ABEObjectsModel, ResourceModel, db, FavoritesMiddle
from sqlalchemy import or_

bp = Blueprint('resource', __name__, url_prefix='/resource')
enc_types=['bsw07','rsa24']

@bp.before_request
def before_request():
    if g.user:
        pass
    else:
        return '未登录'


@bp.route('/')
def index():
    return render_template('resource.html')


@bp.route('/upload_file', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'GET':
        attributes = AttributesModel.query.all()
        return render_template('resource/upload_file.html', attributes=attributes)
    else:
        file = request.files.get('file')
        description = request.form.get('description')
        policy = request.form.get('policy').strip()
        encrypt_type=request.form.get('encrypt_type')
        if policy:
            lc = policy.count('(')
            rc = policy.count(')')
            if lc!=rc:
                return '不合法的访问结构'
            if current_app.config['USE_BASE']:
                base_attr = AttributesModel.query.filter_by(is_base=True).first().name
                if base_attr:
                    policy = base_attr + ' and (' + policy + ')'
        else:
            if current_app.config['USE_BASE']:
                base_attr = AttributesModel.query.filter_by(is_base=True).first().name
                if base_attr:
                    policy = base_attr
        if file and (encrypt_type in enc_types):
            if encrypt_type=='bsw07':
                # 取公共参数
                pk = ABEObjectsModel.query.filter_by(name='07pk').first()
                if not pk:
                    raise Exception('系统未初始化')
                # 准备加密算法
                pairing_group = PairingGroup('SS512')
                cpabe = CPabe_BSW07(pairing_group)
                pk = bytesToObject(pk.object_bytes, pairing_group)
                # 加密对称密钥
                msg = pairing_group.random(GT)
                msgbytes = objectToBytes(msg, pairing_group)
                c = cpabe.encrypt(pk, msg, policy)
                cbytes = objectToBytes(c, pairing_group)
            else:
                # 取公共参数
                pk = ABEObjectsModel.query.filter_by(name='24pk').first().object_bytes
                if not pk:
                    raise Exception('系统未初始化')
                # 准备加密算法
                cpabe = CPabe_RSA24()
                pk = json.loads(pk)
                # 加密对称密钥
                msg = random.randint(0,2^512)
                msgbytes = msg.to_bytes(512,byteorder='big')
                c = cpabe.encrypt(pk, msg, policy)
                cbytes = json.dumps(c).encode('utf8')
            # 对称加密文件
            encid = uuid4().hex
            encname = 'storage/' + encid + '.enc'
            encrypt_file(file, encname, msgbytes)
            file_resource = ResourceModel(id=encid, name=file.filename, file_path=encname, policy=policy,
                                          abe_cipher=cbytes, description=description, resource_type='file',
                                          owner=g.user, encrypt_type=encrypt_type)
            db.session.add(file_resource)
            db.session.commit()
            return render_template('middle_page.html', url=url_for('resource.search_resource'),
                                   message='上传加密成功')
        else:
            return '请选择文件，指定访问结构'


@bp.route('upload_text', methods=['GET', 'POST'])
def upload_text():
    if request.method == 'GET':
        attributes = AttributesModel.query.all()
        return render_template('resource/upload_text.html',attributes=attributes)
    else:
        text = request.form.get('text')
        description = request.form.get('description')
        policy = request.form.get('policy').strip()
        name = request.form.get('name')
        encrypt_type = request.form.get('encrypt_type')
        if policy:
            lc = policy.count('(')
            rc = policy.count(')')
            if lc!=rc:
                return '不合法的访问结构'
            if current_app.config['USE_BASE']:
                base_attr = AttributesModel.query.filter_by(is_base=True).first().name
                if base_attr:
                    policy = base_attr + ' and (' + policy + ')'
        else:
            if current_app.config['USE_BASE']:
                base_attr = AttributesModel.query.filter_by(is_base=True).first().name
                if base_attr:
                    policy = base_attr
        if text and name and (encrypt_type in enc_types):
            if encrypt_type == 'bsw07':
                # 取公共参数
                pk = ABEObjectsModel.query.filter_by(name='07pk').first()
                if not pk:
                    raise Exception('系统未初始化')
                # 准备加密算法
                pairing_group = PairingGroup('SS512')
                cpabe = CPabe_BSW07(pairing_group)
                pk = bytesToObject(pk.object_bytes, pairing_group)
                # 加密对称密钥
                msg = pairing_group.random(GT)
                msgbytes = objectToBytes(msg, pairing_group)
                c = cpabe.encrypt(pk, msg, policy)
                cbytes = objectToBytes(c, pairing_group)
            else:
                # 取公共参数
                pk = ABEObjectsModel.query.filter_by(name='24pk').first().object_bytes
                if not pk:
                    raise Exception('系统未初始化')
                # 准备加密算法
                cpabe = CPabe_RSA24()
                pk = json.loads(pk)
                # 加密对称密钥
                msg = random.randint(0, 2 ^ 512)
                msgbytes = msg.to_bytes(512, byteorder='big')
                c = cpabe.encrypt(pk, msg, policy)
                cbytes = json.dumps(c).encode('utf8')
            # 对称加密文件
            encid = uuid4().hex
            encname = 'storage/' + encid + '.enc'
            encbytes = encrypt_bytes(text.encode('utf8'), msgbytes)
            with open(encname, 'wb') as file:
                file.write(encbytes)
            file_resource = ResourceModel(id=encid, name=name, file_path=encname, policy=policy,
                                          abe_cipher=cbytes, description=description, resource_type='text',
                                          owner=g.user,encrypt_type=encrypt_type)
            db.session.add(file_resource)
            db.session.commit()
            return render_template('middle_page.html', url=url_for('resource.search_resource'),
                                   message='上传加密成功')
        else:
            return '请输入名称、文件内容，指定访问结构'


@bp.route('/search_resource')
def search_resource():
    if request.method == 'GET':
        key_word = request.args.get('key_word')
        if key_word:
            resources = ResourceModel.query.filter(or_(
        ResourceModel.name.contains(key_word),
        ResourceModel.description.contains(key_word)
    )).all()
        else:
            resources = ResourceModel.query.all()
        return render_template('resource/search_resource.html', resources=resources)


@bp.route('/get_resource/<string:resource_id>')
def get_resource(resource_id):
    resource = ResourceModel.query.filter_by(id=resource_id).first()
    if resource is None:
        return '资源不存在'
    if resource.encrypt_type=='bsw07':
        pk = ABEObjectsModel.query.filter_by(name='07pk').first()
        msk = ABEObjectsModel.query.filter_by(name='07msk').first()
        if not (pk and msk):
            raise Exception('系统未初始化')
        pairing_group = PairingGroup('SS512')
        cpabe = CPabe_BSW07(pairing_group)
        pk = bytesToObject(pk.object_bytes, pairing_group)
        msk = bytesToObject(msk.object_bytes, pairing_group)
        attributes = [attribute.name for attribute in g.user.attributes]
        secret_key = cpabe.keygen(pk, msk, attributes)
        cbytes = resource.abe_cipher
        c = bytesToObject(cbytes, pairing_group)
        msg = cpabe.decrypt(pk, secret_key, c)
        if not msg:
            return render_template('middle_page.html', url=url_for('resource.search_resource'),
                                   message='属性不符合访问结构')
        msgbytes = objectToBytes(msg, pairing_group)
    else:
        pk = ABEObjectsModel.query.filter_by(name='24pk').first()
        msk = ABEObjectsModel.query.filter_by(name='24msk').first()
        if not (pk and msk):
            raise Exception('系统未初始化')
        cpabe = CPabe_RSA24()
        pk = json.loads(pk.object_bytes)
        msk = json.loads(msk.object_bytes)
        attributes = [attribute.name for attribute in g.user.attributes]
        secret_key = cpabe.keygen(pk, msk, attributes)
        cbytes = resource.abe_cipher
        c = json.loads(cbytes.decode('utf8'))
        msg = cpabe.decrypt(pk, secret_key, c)
        if not msg:
            return render_template('middle_page.html', url=url_for('resource.search_resource'),
                                   message='属性不符合访问结构')
        msgbytes = msg.to_bytes(512, byteorder='big')
    file = decrypt_file(resource.file_path, msgbytes)
    if resource.resource_type == 'file':
        response = send_file(
            BytesIO(file),  # 使用BytesIO包装bytes数据
            as_attachment=True,  # 告诉浏览器这应该作为一个附件下载
            attachment_filename=resource.name,  # 设定下载时显示的文件名
            mimetype='application/octet-stream'  # 或根据实际文件类型设定mimetype
        )
        return response
    else:
        text = file.decode('utf8')
        return render_template('resource/show_text.html', text=text)


@bp.route('/my_resource')
def my_resource():
    resources = ResourceModel.query.filter_by(owner=g.user)
    return render_template('resource/my_resource.html', resources=resources)


@bp.route('/delete_resource/<string:resource_id>')
def delete_resource(resource_id):
    resource = ResourceModel.query.filter_by(id=resource_id).first()
    if resource and resource.owner == g.user:
        encf_path = 'storage/' + resource.id + '.enc'
        remove(encf_path)
        db.session.delete(resource)
        db.session.commit()
        return redirect(url_for('resource.my_resource'))
    return '资源不可访问'

@bp.route('/favorite_resource/<string:resource_id>')
def favorite_resource(resource_id):
    resource_middle = FavoritesMiddle.query.filter_by(user_id=g.user.id,resource_id=resource_id).first()
    if resource_middle:
        return render_template('middle_page.html',url=request.referrer,message='已收藏过')
    else:
        db.session.add(FavoritesMiddle(user_id=g.user.id,resource_id=resource_id))
        db.session.commit()
        return render_template('middle_page.html',url=request.referrer,message='收藏成功')

@bp.route('/unfavorite_resource/<string:resource_id>')
def unfavorite_resource(resource_id):
    resource_middle = FavoritesMiddle.query.filter_by(user_id=g.user.id,resource_id=resource_id).first()
    if resource_middle:
        db.session.delete(resource_middle)
        db.session.commit()
        return redirect(request.referrer)
    else:
        return '尚未收藏'

@bp.route('/favorites')
def favorites():
    resources=g.user.favorites
    return render_template('resource/favorites.html', resources=resources)