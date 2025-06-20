#python init_db.py でDBを初期化するスクリプト
import os
from app import app
from db_models import db, User, UserActivity

# backendディレクトリの絶対パスを取得
basedir = os.path.abspath(os.path.dirname(__file__))
# instanceフォルダのパス
instance_path = os.path.join(basedir, 'instance')

# instanceフォルダがなければ作成
if not os.path.exists(instance_path):
    os.makedirs(instance_path)

# Flaskの設定をinstanceフォルダ内のDBファイルに合わせて変更
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(instance_path, 'users.db')

with app.app_context():
    db.create_all()
    print("DB初期化完了：User / UserActivity テーブルが作成されました")
