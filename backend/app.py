import sys
import os

# 自分のモジュールを使うためにパスを追加（最初に行う）
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

import datetime
import requests
import traceback
import time
from flask import Flask, jsonify, request, abort, make_response
from flask_cors import CORS
from dotenv import load_dotenv
from flask_mail import Mail, Message
import jwt
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from db_models import db, User, UserActivity
from sqlalchemy.exc import OperationalError
import secrets

print(f'生成されたkey{secrets.token_urlsafe(32)}')

load_dotenv()  # .envの読み込み

app = Flask(__name__)
CORS(app, supports_credentials=True)

print(type(app))

# DB設定
# app.pyがあるディレクトリの絶対パスを取得
basedir = os.path.abspath(os.path.dirname(__file__)) # ここが `backend/` のパスになる
# instanceディレクトリのパスを結合 (backend/instance/)
instance_path = os.path.join(basedir, 'instance')

# instanceディレクトリが存在しない場合は作成
if not os.path.exists(instance_path):
    os.makedirs(instance_path) # これで `backend/instance` ディレクトリが自動的に作成される

# データベースURIに絶対パスを使用
# 例: sqlite:////Users/youruser/your_project/JapanNewsAI/backend/instance/users.db
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(instance_path, 'users.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'connect_args' : {'timeout': 10}
}
db.init_app(app)

# Blueprintの登録（ユーザー情報取得API）
try:
    from api.userinfo import userinfo_bp
    app.register_blueprint(userinfo_bp)
except Exception as e:
    print(f"ユーザー情報取得APIの登録に失敗しました: {e}")

# DBの作成（毎リクエスト前に確認）
@app.before_request
def create_tables():
    db.create_all()

# 環境変数からAPIキーとシークレットキーを取得
GNEWS_API_KEY = os.getenv('GNEWS_API_KEY')
SECRET_KEY = os.getenv('JWT_SECRET_KEY')
REFRESH_SECRET_KEY = os.getenv('REFRESH_TOKEN_SECRET_KEY')

# メール設定
app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER')
app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS', 'True') == 'True'
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
mail = Mail(app)

# ユーザー登録API
@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify(success=False, error='メールアドレスとパスワードが必要です'), 400

    if User.query.filter_by(email=email).first():
        return jsonify(success=False, error='そのメールアドレスは既に登録されています。'), 400

    password_hash = generate_password_hash(password)
    new_user = User(username=username, email=email, password_hash=password_hash)
    db.session.add(new_user)
    db.session.commit()

    return jsonify(success=True)

# ユーザーログインAPI
@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify(success=False, error='メールアドレスとパスワードが必要です'), 400

    user = User.query.filter_by(email=email).first()
    if not user or not check_password_hash(user.password_hash, password):
        return jsonify(success=False, error='メールアドレスまたはパスワードが間違っています。'), 401

    payload = {
        'email': email,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=15)#アクセストークンは短めに15分
    }
    access_token = jwt.encode(payload, SECRET_KEY, algorithm='HS256')
    print(f"DEBUG:ログイン時生成米ロード:{payload}")
    print(f"DEBUG:ログイン対象ユーザー名:{user.username},メール:{user.email}")

    refresh_token_payload = {
        'email': email,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(days=7) #リフレッシュトークンは長めに7日
    }
    refresh_token = jwt.encode(refresh_token_payload, REFRESH_SECRET_KEY, algorithm='HS256')
    print(f"生成されたアクセストークン: {access_token}")
    print(f"生成されたリフレッシュトークン: {refresh_token}")
    response = make_response(jsonify(success=True, token=access_token,username=user.username))
    response.set_cookie(
        'refresh_token',
        refresh_token,
        httponly=True,
        samesite='None',
        secure=True,  #開発中はFalse 本番環境ではtrue
        max_age=datetime.timedelta(days=7).total_seconds()
    )
    return response

# GNews APIを使ってニュースを取得
@app.route('/api/news')
def get_news():
    page = int(request.args.get('page', 1))
    page_size = 5
    start = (page - 1) * page_size

    url = (
        f'https://gnews.io/api/v4/top-headlines'
        f'?lang=ja'
        f'&country=jp'
        f'&max={page_size}'
        f'&apikey={GNEWS_API_KEY}'
        f'&start={start}'
    )

    try:
        response = requests.get(url)
        data = response.json()
        #print(f"[page: {page}] 取得した記事数: {len(data.get('articles', []))}")
        return jsonify(data)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# 認証メール送信
@app.route('/api/send_email', methods=['POST'])
def send_email():
    data = request.get_json()
    recipient = data.get('email')

    if not recipient:
        return jsonify({'error': 'メールアドレスが指定されていません'}), 400

    try:
        #このJWTトークンは、メール認証用なので、有効期限は短くて良い
        payload = {
            'email': recipient,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)
        }
        token = jwt.encode(payload, SECRET_KEY, algorithm='HS256')
        print(f"生成されたトークン: {token}")

        verify_url = f"http://localhost:3000/verify?token={token}"

        msg = Message(
            subject='[認証]あなたのログインリンク',
            sender=app.config['MAIL_USERNAME'],
            recipients=[recipient],
            body=f"こちらのリンクをクリックしてログインしてください:\n\n{verify_url}"
        )
        mail.send(msg)
        print(f"認証メールを {recipient} に送信しました")
        return jsonify(success=True, message='認証メールを送信しました')
    except Exception as e:
        traceback.print_exc() #詳細ログ出力
        return jsonify(success=False, error=str(e)), 500

# トークンの検証
@app.route('/api/verify_token', methods=['POST'])
def verify_token():
    print("verify_token にリクエストが届きました")
    data = request.get_json()
    print("受け取ったデータ:", data)
    token = data.get('token')

    if not token:
        return jsonify(success=False, error="トークンがありません"), 400

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        print(f"DEBUG: verify_token でデコードされたペイロード: {payload}")
        email = payload.get('email')
        user = User.query.filter_by(email=email).first()
        if not user:
            return jsonify(success=False, error="ユーザーが見つかりません"), 404

        return jsonify(success=True, username=user.username, token=token)
    except jwt.ExpiredSignatureError:
        return jsonify(success=False, error="トークンの有効期限が切れています"), 401
    except jwt.InvalidTokenError:
        return jsonify(success=False, error="無効なトークンです"), 400

#トークンリフレッシュAPIを追加
@app.route('/api/refresh_token', methods=['POST'])
def refresh_token():
    refresh_token = request.cookies.get('refresh_token')

    if not refresh_token:
        return jsonify(success=False, error='リフレッシュトークンがありません'), 401

    try:
        #トークンリフレッシュAPIを追加
        payload = jwt.decode(refresh_token, REFRESH_SECRET_KEY, algorithms=['HS256'])
        email = payload.get('email')

        user = User.query.filter_by(email=email).first()
        if not user:
            return jsonify(success=False, error='ユーザーが見つかりません'), 404

        #新しいアクセストークンを発行
        new_access_token_payload = {
            'email': email,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=15) #新しいアクセストークンも15分
        }
        new_access_token = jwt.encode(new_access_token_payload, SECRET_KEY, algorithm='HS256')

        response = make_response(jsonify(success=True, token=new_access_token, username=user.username))
        #必要であれば、リフレッシュトークンも更新してCookieを歳せて地することも可能(セキュリティー強化のため)
        #今回はシンプルにアクセストークンのみ更新
        return response
    except jwt.ExpiredSignatureError:
        #リフレッシュトークンも期限切れの場合
        response = make_response(jsonify(success=False, error='リフレッシュトークンの有効期限が切れました。再ログインが必要です。'), 401)
        response.delete_cookie('refresh_token') #無効なリフレッシュトークンを削除
        return response
    except jwt.InvalidTokenError:
        #無効なリフレッシュトークンの場合
        response = make_response(jsonify(success=False, error='無効なリフレッシュトークンです。再ログインが必要です。'), 401)
        response.delete_cookie('refresh_token') #無効なリフレッシュトークンを削除
        return response

#ユーザーのアクティビティを記録するAPI
@app.route('/api/user_activity', methods=['POST'])
def user_activity():
    data = request.get_json()
    auth_header = request.headers.get('Authorization', '')
    if not auth_header.startswith('Bearer '):
        return jsonify(success=False, error='Authorizationヘッダーが不正です'), 401
    token = auth_header[len('Bearer '):]

    #ここでjwtトークンの検証をしてユーザーを特定する
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        email = payload.get('email')
        user = User.query.filter_by(email=email).first()
        if not user:
            return jsonify(success=False, error='ユーザーが見つかりません'), 404
        user_id = user.id
    except jwt.ExpiredSignatureError:
        return jsonify(success=False, error='トークンの有効期限が切れています'), 401
    except jwt.InvalidTokenError:
        return jsonify(success=False, error='無効なトークンです'), 400
    # Added general exception handling for JWT issues if they occur before specific ones.
    except Exception as e: # JWT検証中に予期せぬエラーが発生した場合の追加ハンドリング
        print(f"ERROR: ユーザーアクティビティのJWT検証中に予期せぬエラーが発生しました: {e}")
        return jsonify(success=False, error=f"認証エラー: {str(e)}"), 500


    activity_type = data.get('activity_type')
    article_id = data.get('article_id')
    article_title = data.get("article_title")
    article_description = data.get('article_description')

    if not activity_type or not article_id:
        return jsonify(success=False, error="activity_typeとarticle_idが必要です"), 400

    activity = UserActivity(
        user_id=user_id,
        activity_type=activity_type,
        article_id=article_id,
        article_title=article_title,
        article_description=article_description
    )
    max_retries = 3
    retry_delay_seconds = 0.1
    for i in range(max_retries):
        try:
            db.session.add(activity)
            db.session.commit()
            print(f"DEBUG:ユーザーアクティビティがDBに正常に保存されました:"
                f"User ID={user_id}, Type={activity_type}, Article ID={article_id}")
            return jsonify(success=True, message="アクティビティを記録しました"), 200
        except OperationalError as e:
            db.session.rollback() # エラーが発生したらロールバック
            # 「database is locked」エラーの場合、かつリトライ回数が残っている場合
            if "database is locked" in str(e).lower() and i < max_retries - 1:
                print(f"WARNING: データベースがロックされています。リトライします ({i+1}/{max_retries}). エラー: {e}")
                time.sleep(retry_delay_seconds) # 少し待機
            else:
                # リトライ上限に達したか、ロック以外のOperationalErrorの場合
                print(f"ERROR: データベース操作に失敗しました (リトライ上限に達したか、その他のOperationalError): {e}")
                traceback.print_exc()
                return jsonify(success=False, error=f"アクティビティ記録失敗: {str(e)}"), 500
        except Exception as e:
            # OperationalError以外の予期せぬエラーの場合
            db.session.rollback()
            print(f"ERROR:ユーザアクティビティのDB保存に失敗しました:{e}")
            traceback.print_exc()
            return jsonify(success=False, error=f"アクティビティ記録失敗:{str(e)}"), 500

    # ここに到達した場合、すべてのリトライが失敗したことを意味する
    return jsonify(success=False, error="アクティビティ記録が複数回失敗しました。時間をおいてお試しください。"), 500


# ユーザーアクティビティをもとに推薦記事を取得するAPI
@app.route('/api/recommendations', methods=['GET'])
def get_recommendations():
    auth_header = request.headers.get('Authorization', '')
    if not auth_header.startswith('Bearer '):
        return jsonify(success=False, error='認証ヘッダーが不正です'), 401
    token = auth_header[len('Bearer '):]

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        email = payload.get('email')
        user = User.query.filter_by(email=email).first()
        if not user:
            return jsonify(success=False, error='ユーザーが見つかりません'), 404
        user_id = user.id
    except jwt.ExpiredSignatureError:
        return jsonify(success=False, error='トークンの有効期限が切れています'), 401
    except jwt.InvalidTokenError:
        return jsonify(success=False, error='無効なトークンです'), 400
    except Exception as e: # Catch any other unexpected JWT related errors
        print(f"ERROR in get_recommendations token decoding: {e}")
        traceback.print_exc()
        return jsonify(success=False, error=f'トークン処理中に予期せぬエラーが発生しました: {str(e)}'), 500

    # Start recommendation logic
    # 1. Extract keywords from user browsing history
    user_views = UserActivity.query.filter_by(user_id=user_id, activity_type='view').all()

    # Store URLs of read articles in a set (for duplication check)
    viewed_article_urls = {activity.article_id for activity in user_views}

    keywords = {}
    for activity in user_views:
        if activity.article_title:
        # Count keywords by splitting article title (simplified)
            for word in activity.article_title.split():
                if len(word) > 2 and word.lower() not in ['の', 'に', 'は', 'が', 'を', 'と', 'で', 'も', 'から', 'まで', 'そして', 'しかし', 'ある', 'いる', 'する', 'なる', 'れる', 'など', 'こと', 'もの', 'それ']:
                    keywords[word.lower()] = keywords.get(word.lower(), 0) + 1
        if activity.article_description:
            for word in activity.article_description.split():
                if len(word) > 2 and word.lower() not in ['の', 'に', 'は', 'が', 'を', 'と', 'で', 'も', 'から', 'まで', 'そして', 'しかし', 'ある', 'いる', 'する', 'なる', 'れる', 'など', 'こと', 'もの', 'それ']:
                    keywords[word.lower()] = keywords.get(word.lower(), 0) + 1

    # Sort keywords by frequency and get the top ones
    # Extract top 5 keywords
    sorted_keywords = sorted(keywords.items(), key=lambda item: item[1], reverse=True)[:5]
    query_words = [word for word, count in sorted_keywords]

    recommended_articles = []

    if query_words:
        # Search for articles based on keywords using GNews API
        search_query = ' OR '.join(query_words)
        print(f"DEBUG: Recommended article search query: {search_query}")

        url = (
            f'https://gnews.io/api/v4/search'
            f'?q={search_query}'
            f'&country=jp'
            f'&max=10'
            f'&apikey={GNEWS_API_KEY}'
        )
        try:
            response = requests.get(url)
            data = response.json()

            if data.get('articles'):
                for article in data['articles']:
                    # Exclude already read articles
                    if article.get('url') not in viewed_article_urls:
                        recommended_articles.append(article)
                    if len(recommended_articles) >= 5: # Recommend up to 5 articles
                        break
        except Exception as e:
            print(f"ERROR: An error occurred while fetching recommended articles: {e}")
    # Fallback if no query keywords or no articles found from GNews API
    if not recommended_articles:
        # Fetch latest articles as fallback
        print("DEBUG: No recommended articles found, fetching latest articles as fallback.")
        url = (
            f'https://gnews.io/api/v4/top-headlines'
            f'?lang=ja'
            f'&country=jp'
            f'&max=5' # 5 latest articles
            f'&apikey={GNEWS_API_KEY}'
        )
        try:
            response = requests.get(url)
            data = response.json()
            if data.get('articles'):
                for article in data['articles']:
                    if article.get('url') not in viewed_article_urls: # Exclude already read articles in fallback
                        recommended_articles.append(article)
                    if len(recommended_articles) >= 5:
                        break
        except Exception as e:
            print(f"ERROR: An error occurred while fetching fallback articles: {e}")

    print(f"DEBUG: Returning {len(recommended_articles)} recommended articles.")
    return jsonify(articles=recommended_articles)

# Simple test endpoint
@app.route('/api/hello')
def hello():
    return jsonify(message='Flask api reply')

if __name__ == '__main__':
    app.run(debug=True)