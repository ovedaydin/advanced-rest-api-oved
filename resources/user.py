from flask_restful import Resource, reqparse
from werkzeug.security import safe_str_cmp
from flask_jwt_extended import (
    create_access_token, 
    create_refresh_token, 
    jwt_refresh_token_required, 
    get_jwt_identity,
    jwt_required,
    get_raw_jwt
)
from models.user import UserModel
from blacklist import BLACKLIST


_user_parser = reqparse.RequestParser()
_user_parser.add_argument('username',type=str,required=True,help="This field cannot be left blank!")
_user_parser.add_argument('password',type=str,required=True,help="This field cannot be left blank!")


class UserRegister(Resource):
    def post(self):

        data = _user_parser.parse_args()

        if UserModel.find_by_username(data['username']):
            return {"message":"A User with that username exists"}, 400

        user = UserModel(**data) #**data = data['username'],data['password']
        user.save_to_db()

        return {"message":"User created"}, 201

class User(Resource):
    @classmethod
    def get(cls, user_id):
        user = UserModel.find_by_id(user_id)
        if not user:
            return {'message':'User not found'} , 404
        return user.json()
        

    def delete(cls, user_id):
        user = UserModel.find_by_id(user_id)
        if not user:
            return {'message':'User not found'} , 404
        user.delete_from_db()
        return {'meessage':'User deleted'}

class UserLogin(Resource):
    @classmethod 
    def post(cls):
        # get data from parser
        data = _user_parser.parse_args()

        # find user in database
        user = UserModel.find_by_username(data['username'])
        # check password
        # create access token
        # create refresh token
        # return them

        if user and safe_str_cmp(user.password, data['password']):
            access_token = create_access_token(identity=user.id,fresh=True)
            refresh_token = create_refresh_token(user.id)
            return {'access_token' : access_token,'refresh_token' : refresh_token},200
        
        return {'message':'Invalid credentials.'},401

class UserLogout(Resource):
    @jwt_required
    def post(self):
        jti = get_raw_jwt()['jti']
        BLACKLIST.add(jti)
        print(BLACKLIST)
        return {'message': 'Successfully logged out!'}, 200



class TokenRefresher(Resource):
    @jwt_refresh_token_required
    def post(self):
        current_user = get_jwt_identity()
        new_token = create_access_token(identity=current_user, fresh=False)
        return {'acces_token': new_token}, 200



