from flask import Flask, jsonify, abort, make_response, request, url_for
import json
import hashlib
import binascii
import os
import datetime

app = Flask(__name__)


def hash_password(password: str) -> str:
    """
    Функция хэширования паролей
    :param password:
    :return hash password:
    """
    salt = hashlib.sha256(os.urandom(60)).hexdigest().encode('ascii')
    pwdhash = hashlib.pbkdf2_hmac('sha512', password.encode('utf-8'), salt, 100000)
    pwdhash = binascii.hexlify(pwdhash)
    return (salt + pwdhash).decode('ascii')


def change_user_info(user):
    new_ret_user = {}
    for key in user:
        if key == 'id':
            new_ret_user['uri'] = url_for('get_user', user_id=user['id'], _external=True)
        new_ret_user[key] = user[key]
    return new_ret_user


@app.route('/')
def index():
    return "Привет МИР"


@app.route('/users', methods=['GET'])
def get_users():
    return jsonify({"users": list(map(change_user_info, users))})


@app.route('/users/<int:user_id>', methods=['GET'])
def get_user(user_id):
    user = list(filter(lambda x: x['id'] == user_id, users))
    if len(user) == 0:
        abort(404)
    return jsonify({'users': user[0]})


@app.route('/users/<string:user_login>', methods=['GET'])
def get_user_str(user_login):
    user = list(filter(lambda x: x['login'] == user_login, users))
    if len(user) == 0:
        abort(404)
    return jsonify({'users': user[0]})


@app.errorhandler(404)
def not_found(error):
    return make_response(jsonify({'error': 'Not found'}), 404)


@app.errorhandler(400)
def bad_request(error):
    return make_response(jsonify({"error": "Bad Request"}), 400)


@app.route('/users', methods=['POST'])
def create_user():
    if not request.json or 'login' not in request.json:
        abort(400)

    user = list(filter(lambda x: x['login'] == request.json['login'], users))

    if len(user)>0:
        abort(400)

    try:
        user_new = {
            'id': users[-1]['id'] + 1,
            'login': request.json['login'],
            'password': hash_password(request.json.get('password', '1234')),
            'regDate': datetime.datetime.now().isoformat()
        }
    except IndexError:
        user_new = {
            'id': 1,
            'login': request.json['login'],
            'password': hash_password(request.json.get('password', '1234')),
            'regDate': datetime.datetime.now().isoformat()
        }
    users.append(user_new)
    with open('users.json', 'w') as json_file:
        json.dump(users, json_file)
    return jsonify({'user': user_new}), 201



try:
    with open('users.json', 'r') as json_file:
        users = json.load(json_file)
except FileNotFoundError:
    users = []
    with open('users.json', 'w') as json_file:
        json.dump(users, json_file)

if __name__ == '__main__':
    app.run(ssl_context=('certs/cert.pem', 'certs/key.pem'))
