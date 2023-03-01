import datetime
import hashlib

from flask import Flask, jsonify, request
from flask_jwt_extended import (JWTManager, create_access_token,
                                get_jwt_identity, jwt_required)
from pymongo import MongoClient

app = Flask(__name__)
jwt = JWTManager(app)

app.config['JWT_SECRET_KEY'] = 'super-secret-key'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = datetime.timedelta(days=1)

client = MongoClient('mongodb://localhost:27017/')
db = client['flask-db']
users_collection = db['users']


def find_current_user():
    current_user = get_jwt_identity()
    user_from_db = users_collection.find_one({'username': current_user})

    return user_from_db


@app.route('/api/v1/register', methods=['POST'])
def register():
    new_user = request.get_json()
    new_user['password'] = hashlib.sha256(
        new_user['password'].encode()).hexdigest()

    doc = users_collection.find_one({'username': new_user['username']})

    if not doc:
        users_collection.insert_one(new_user)
        return jsonify({'message': 'User created successfully'}), 201

    else:
        return jsonify({'message': 'User already exists'}), 409


@app.route('/api/v1/login', methods=['POST'])
def login():
    login_details = request.get_json()
    user_from_db = users_collection.find_one(
        {'username': login_details['username']})

    if user_from_db:
        encrypted_password = hashlib.sha256(
            login_details['password'].encode('utf-8')).hexdigest()

        if encrypted_password == user_from_db['password']:
            access_token = create_access_token(
                identity=user_from_db['username'])

            return jsonify({'message': 'Login successful', 'access_token': access_token}), 200

    else:
        return jsonify({'message': 'An user with given username does not exist'}), 401

    return jsonify({'message': 'Invalid credentials, check your password'}), 401


@app.route('/api/v1/users', methods=['GET'])
@jwt_required(verify_type=False)
def get_users():
    users = users_collection.find({}, {'_id': 0})
    return jsonify({'users': list(users)}), 200


@app.route('/api/v1/user', methods=['GET'])
@jwt_required(verify_type=False)
def get_current_user():
    user_from_db = find_current_user()

    if user_from_db:
        del user_from_db['_id']
        return jsonify({'user': user_from_db}), 200

    else:
        return jsonify({'message': 'An user with given username does not exist'}), 401


@app.route('/api/v1/user', methods=['DELETE'])
@jwt_required(verify_type=False)
def delete_current_user():
    user_from_db = find_current_user()

    if user_from_db:
        users_collection.find_one_and_delete(
            {'username': user_from_db['username']})

        return jsonify({'message': 'User deleted successfully!'}), 200

    else:
        return jsonify({'message': 'An user with given username does not exist'}), 401


@app.route('/api/v1/user', methods=['PUT'])
@jwt_required(verify_type=False)
def update_current_user():
    user_from_db = find_current_user()

    if user_from_db:
        new_user = request.get_json()

        user_from_db['username'] = new_user['username']
        user_from_db['password'] = new_user['password']

        users_collection.find_one_and_update(
            {'username': user_from_db['username']},
            {'$set': user_from_db}
        )

        del user_from_db['_id']
        return jsonify({'user': user_from_db}), 200

    else:
        return jsonify({'message': 'An user with given username does not exist'}), 401


if __name__ == '__main__':
    app.run(debug=True)
