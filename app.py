import os

from flask import Flask, jsonify
from flask_restful import Api 
from flask_jwt_extended import JWTManager

from resources.user import UserRegister, User, UserLogin, TokenRefresher, UserLogout
from blacklist import BLACKLIST
app = Flask(__name__)

app.config['DEBUG'] = True
app.config['SQLALCHEMY_DATABASE_URI'] = ('sqlite:///data.db') #  os.environ.get ('DATABASE_URL',
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['PROPAGATE_EXCEPTIONS'] = True
app.config['JWT_BLACKLIST_ENABLED'] = True
app.config['JWT_BLACKLIST_TOKEN_CHECKS'] = ['access','refresh']
app.secret_key = 'oved' #app.config['JWT_SECRET_KEY']
api = Api(app)

@app.before_first_request
def create_tables():
    db.create_all()


jwt = JWTManager(app)  # /auth

@jwt.user_claims_loader
def add_claims_to_jwt(identity):
    if identity == 1:
        return {'is_admin': True}
    return{'is_admin': False}

@jwt.token_in_blacklist_loader
def check_if_token_in_blacklist(decrypted_token):
     return decrypted_token['jti'] in BLACKLIST

@jwt.expired_token_loader
def expired_token_callback():
    return jsonify({'description': 'The token has expired','error':'token_expired'}), 401

@jwt.invalid_token_loader #blacklisted
def invalid_token_callback(error):
    return jsonify({'description': 'What are you doing?','error':'invalid token'}), 401 

@jwt.unauthorized_loader
def unauthorized_callback():
    return jsonify({'description': 'Tanrı aşkına','error':'unauthorized'}), 401

@jwt.needs_fresh_token_loader
def needs_fresh_token_callback():
    return jsonify({'description': 'Olmadı bu','error':'needs fresh token'}), 401

@jwt.revoked_token_loader
def revoked_token_callback():
    return jsonify({'description': 'Tokeni iptal ettik kusura bakma','error':'token_revoked'}), 401


api.add_resource(UserRegister, '/register')
api.add_resource(User, '/user/<int:user_id>')
api.add_resource(UserLogin, '/login')
api.add_resource(UserLogout,'/logout')
api.add_resource(TokenRefresher,'/refresh')

if __name__ == '__main__':
    from db import db
    db.init_app(app)

    if app.config['DEBUG']:
        @app.before_first_request
        def create_tables():
            db.create_all()

    app.run(port=5000)
