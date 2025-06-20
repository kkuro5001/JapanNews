# リクエスト
#   ↓ Authorizationヘッダーを確認
#   ↓ トークンを取り出して検証
#   ↓ トークンが有効ならemailを取得
#   ↓ DBでユーザー検索
#   ↓ 情報を返す or エラー

from flask import Blueprint, request, jsonify
import jwt
from db_models import User
import os

userinfo_bp = Blueprint('userinfo_bp', __name__)
SECRET_KEY = os.getenv('JWT_SECRET_KEY')

@userinfo_bp.route('/api/userinfo', methods=['GET'])
def userinfo():
    auth_header = request.headers.get('Authorization')
    if not auth_header:
        return jsonify({'error': '認証情報がありません'}), 401

    try:
        token = auth_header.split(' ')[1] #Bearer <token> 形式を想定
        payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        email = payload.get('email')

        user = User.query.filter_by(email=email).first()
        if not user:
            return jsonify({'error': 'ユーザーが見つかりません'}), 404

        return jsonify({'username': user.username, 'email': user.email})

    except jwt.ExpiredSignatureError:
        return jsonify({'error': 'トークンの有効期限が切れています'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'error': '無効なトークンです'}), 401
    except Exception as e:
        return jsonify({'error': str(e)}), 500