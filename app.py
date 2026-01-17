from flask import Flask, request, jsonify, render_template, session, send_file
from functools import wraps
import boto3
from botocore.exceptions import ClientError
import uuid
from datetime import datetime, timedelta
import os
import tempfile
import zipfile
import threading
import time
from dotenv import load_dotenv
from PIL import Image, ImageOps
import ffmpeg
import bcrypt

# 環境変数を読み込み
load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')

# 開発環境かどうかを判定
# Flaskのデバッグモードは以下の方法で判定可能：
# 1. app.debug (Flask起動時に設定される)
# 2. FLASK_DEBUG環境変数 (Flask 2.2以降、推奨)
# 3. app.config.get('DEBUG')
# 環境変数で明示的にHTTPS強制を制御可能にする
FORCE_HTTPS = os.environ.get('FORCE_HTTPS', 'false').lower() == 'true'
# FLASK_DEBUG環境変数も確認（Flask 2.2以降で使用可能、推奨方法）
FLASK_DEBUG = os.environ.get('FLASK_DEBUG', '').lower() in ('1', 'true', 'on')

# セッションクッキーのセキュリティ設定
# 重要: SameSite=Noneを使用する場合、Secure=Trueが必須（モダンブラウザの要件）
# 開発環境（HTTP）ではSameSite='Lax'を使用し、本番環境（HTTPS）ではSameSite='None'を使用

# 環境変数で明示的に制御可能にする
# 環境変数が設定されているかどうかをチェックするため、元の値を保持
SESSION_COOKIE_SECURE_ENV = os.environ.get('SESSION_COOKIE_SECURE', '')
SESSION_COOKIE_SAMESITE_ENV = os.environ.get('SESSION_COOKIE_SAMESITE', '')
SESSION_SECURE = SESSION_COOKIE_SECURE_ENV.lower() if SESSION_COOKIE_SECURE_ENV else ''
SESSION_SAMESITE = SESSION_COOKIE_SAMESITE_ENV.lower() if SESSION_COOKIE_SAMESITE_ENV else ''

# Secure属性の設定
if SESSION_SECURE == 'true':
    app.config['SESSION_COOKIE_SECURE'] = True
elif SESSION_SECURE == 'false':
    app.config['SESSION_COOKIE_SECURE'] = False
else:
    # デフォルト: 開発環境ではFalse、本番ではTrue
    # app.debugは起動時に設定されるため、初期値はFalseに設定し、
    # before_requestでapp.debugに基づいて動的に調整する
    app.config['SESSION_COOKIE_SECURE'] = False

app.config['SESSION_COOKIE_HTTPONLY'] = True

# SameSite属性の設定
# 環境変数で明示的に設定されている場合はそれを使用
if SESSION_SAMESITE in ('none', 'lax', 'strict'):
    app.config['SESSION_COOKIE_SAMESITE'] = SESSION_SAMESITE.capitalize()
    # SameSite=Noneを使用する場合、Secure=Trueが必須（モダンブラウザの要件）
    if app.config['SESSION_COOKIE_SAMESITE'] == 'None' and not app.config['SESSION_COOKIE_SECURE']:
        # 無効な組み合わせを防ぐため、自動的にSecure=Trueに設定
        import warnings
        warnings.warn(
            "SameSite=None requires Secure=True (browser requirement). "
            "Setting SESSION_COOKIE_SECURE=True automatically. "
            "For development over HTTP, consider using SameSite='Lax' instead.",
            UserWarning
        )
        app.config['SESSION_COOKIE_SECURE'] = True
else:
    # デフォルト: Secure=Trueの場合は'None'、Falseの場合は'Lax'
    # SameSite=Noneを使用する場合は、必ずSecure=Trueが必須
    # 初期値はSecure=Falseに基づいて'Lax'に設定し、
    # before_requestでapp.debugに基づいて動的に調整する
    if app.config['SESSION_COOKIE_SECURE']:
        app.config['SESSION_COOKIE_SAMESITE'] = 'None'  # HTTPS環境: クロスサイト対応（fetch APIで必要）
    else:
        app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # HTTP環境: 同一サイトのみ（開発環境向け）

# app.debugに基づいてセッションクッキー設定を動的に調整する関数
def adjust_session_cookie_config():
    """
    app.debugの状態に基づいてセッションクッキー設定を動的に調整
    環境変数で明示的に設定されている場合は変更しない
    """
    # 環境変数で明示的に設定されている場合は調整しない
    # SESSION_COOKIE_SECURE_ENVが空文字列でない場合（環境変数が設定されている場合）は調整しない
    if SESSION_COOKIE_SECURE_ENV:
        return
    
    # app.debugがFalse（本番環境）の場合、Secure=Trueに設定
    # app.debugがTrue（開発環境）の場合、Secure=Falseのまま
    is_development = (
        app.debug or 
        FLASK_DEBUG or 
        app.config.get('DEBUG', False)
    )
    
    if not is_development:
        # 本番環境: Secure=True, SameSite='None'
        app.config['SESSION_COOKIE_SECURE'] = True
        # SameSiteが環境変数で設定されていない場合のみ更新
        if not SESSION_COOKIE_SAMESITE_ENV:
            app.config['SESSION_COOKIE_SAMESITE'] = 'None'
    else:
        # 開発環境: Secure=False, SameSite='Lax'
        app.config['SESSION_COOKIE_SECURE'] = False
        # SameSiteが環境変数で設定されていない場合のみ更新
        if not SESSION_COOKIE_SAMESITE_ENV:
            app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
    
    # SameSite=NoneとSecure=Falseの組み合わせを検証
    if app.config['SESSION_COOKIE_SAMESITE'] == 'None' and not app.config['SESSION_COOKIE_SECURE']:
        import warnings
        warnings.warn(
            "SameSite=None requires Secure=True (browser requirement). "
            "Setting SESSION_COOKIE_SECURE=True automatically.",
            UserWarning
        )
        app.config['SESSION_COOKIE_SECURE'] = True
# セッションの永続化設定
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=7)

# AWS設定（Learner Labでは us-east-1 または us-west-2 のみ利用可能）
AWS_REGION = os.environ.get('AWS_REGION', 'us-east-1')
s3_client = boto3.client('s3', region_name=AWS_REGION)
dynamodb = boto3.resource('dynamodb', region_name=AWS_REGION)
BUCKET_NAME = os.environ.get('S3_BUCKET_NAME', 'photo-video-storage-default')
contents_table = dynamodb.Table('contents')
users_table = dynamodb.Table('users')

# URLキャッシュ（{user_id}:{s3_key} → (url, timestamp)）
_url_cache = {}
_url_cache_ttl = timedelta(hours=1)
_url_cache_lock = threading.RLock()  # 再入可能ロック（スレッドセーフティ用）


def validate_username(username: str) -> tuple[bool, str | None]:
    """
    ユーザー名のバリデーション
    戻り値: (is_valid, error_message)
    """
    if not username:
        return False, 'Username is required'
    if len(username) < 3:
        return False, 'Username must be at least 3 characters'
    if len(username) > 64:
        return False, 'Username must be at most 64 characters'
    return True, None


def validate_password(password: str) -> tuple[bool, str | None, str | None]:
    """
    パスワードのバリデーション
    戻り値: (is_valid, error_message, warning_message)
    warning_message: 推奨事項（エラーではない）
    """
    if not password:
        return False, 'Password is required', None
    if len(password) < 8:
        return False, 'Password must be at least 8 characters', None
    if len(password) > 64:
        return False, 'Password must be at most 64 characters', None
    
    # 英数字記号が利用可能であることを確認
    # 英字、数字、記号のいずれかが含まれているかチェック
    has_letter = any(c.isalpha() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_symbol = any(c in '!@#$%^&*()_+-=[]{}|;:,.<>?/~`' for c in password)
    
    # すべて混合を推奨（必須ではない）
    warning = None
    if not (has_letter and has_digit and has_symbol):
        warning = 'For better security, it is recommended to use a combination of letters, numbers, and symbols'
    
    return True, None, warning


def hash_password(password: str) -> str:
    """パスワードをbcryptでハッシュ化"""
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed.decode('utf-8')


def verify_password(password: str, hashed: str) -> bool:
    """パスワードを検証"""
    try:
        return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))
    except Exception:
        return False


def require_auth(f):
    """認証必須デコレータ"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': 'Authentication required'}), 401
        return f(*args, **kwargs)
    return decorated_function


def sanitize_filename(name: str) -> str:
    """
    HTTPヘッダー用に安全なファイル名にする簡易サニタイズ。
    - CRLF を除去（レスポンススプリッティング対策）
    - ダブルクォート、セミコロンなどの特殊文字を除去
    - 空の場合はデフォルト名を返す
    """
    if not name:
        return "download"
    # CRLF を除去
    sanitized = name.replace("\r", "").replace("\n", "")
    # HTTPヘッダーで問題となる文字を除去
    # ダブルクォート、セミコロン、バックスラッシュを除去
    sanitized = sanitized.replace('"', '').replace(';', '').replace('\\', '')
    # 制御文字（0x00-0x1F、0x7F）を除去
    sanitized = ''.join(char for char in sanitized if ord(char) >= 32 and ord(char) != 127)
    # すべて除去された場合はデフォルト名にフォールバック
    if not sanitized:
        return "download"
    return sanitized


def perform_compression(content_id: str, s3_key: str, content_type: str, upload_date: str) -> dict:
    """
    コンテンツを圧縮する内部関数。
    戻り値: {'success': bool, 'original_size': int, 'compressed_size': int, 'error': str}
    """
    temp_input_path = None
    temp_output_path = None
    
    try:
        # 一時ファイルを作成
        temp_input = tempfile.NamedTemporaryFile(delete=False)
        temp_input_path = temp_input.name
        temp_input.close()

        temp_output = tempfile.NamedTemporaryFile(delete=False)
        temp_output_path = temp_output.name
        temp_output.close()

        # 動画の場合は圧縮をサポートしない
        if content_type.startswith('video/'):
            return {'success': False, 'error': 'Video compression is not supported. Only images can be compressed.'}
        
        # 画像以外のコンテンツタイプはサポートしない
        if not content_type.startswith('image/'):
            return {'success': False, 'error': 'Unsupported content type for compression'}

        # S3からファイルをダウンロード
        s3_client.download_file(BUCKET_NAME, s3_key, temp_input_path)

        # 画像圧縮（Pillow）
        img = Image.open(temp_input_path)
        
        # EXIF Orientation情報を適用して画像を正しい向きに回転
        img = ImageOps.exif_transpose(img)
        
        # RGBに変換（PNGの透過情報などは失われる）
        if img.mode in ('RGBA', 'LA', 'P'):
            # 透過画像の場合は白背景に合成
            background = Image.new('RGB', img.size, (255, 255, 255))
            if img.mode == 'P':
                img = img.convert('RGBA')
            background.paste(img, mask=img.split()[-1] if img.mode in ('RGBA', 'LA') else None)
            img = background
        elif img.mode != 'RGB':
            img = img.convert('RGB')
        
        # JPEG品質75で保存
        img.save(temp_output_path, 'JPEG', quality=75, optimize=True)
        new_content_type = 'image/jpeg'

        # 圧縮後のファイルサイズを取得
        original_size = os.path.getsize(temp_input_path)
        compressed_size = os.path.getsize(temp_output_path)

        # 圧縮後のファイルを同じs3_keyでS3に上書きアップロード
        s3_client.upload_file(
            temp_output_path,
            BUCKET_NAME,
            s3_key,
            ExtraArgs={'ContentType': new_content_type}
        )

        # DynamoDBのメタデータを更新
        contents_table.update_item(
            Key={
                'content_id': content_id,
                'upload_date': upload_date
            },
            UpdateExpression='SET file_size = :fs, compressed = :c, content_type = :ct',
            ExpressionAttributeValues={
                ':fs': compressed_size,
                ':c': True,
                ':ct': new_content_type
            }
        )

        return {
            'success': True,
            'original_size': original_size,
            'compressed_size': compressed_size
        }

    except Exception as e:
        print(f"Compression error: {str(e)}")
        return {'success': False, 'error': str(e)}
    finally:
        # 一時ファイルを削除
        if temp_input_path and os.path.exists(temp_input_path):
            os.remove(temp_input_path)
        if temp_output_path and os.path.exists(temp_output_path):
            os.remove(temp_output_path)


def generate_video_thumbnail(content_id: str, s3_key: str, user_id: str) -> dict:
    """
    動画からサムネイルを生成する関数。
    戻り値: {'success': bool, 'thumbnail_s3_key': str, 'error': str}
    """
    temp_video_path = None
    temp_thumbnail_path = None
    
    try:
        # 一時ファイルを作成
        temp_video = tempfile.NamedTemporaryFile(delete=False, suffix='.mp4')
        temp_video_path = temp_video.name
        temp_video.close()

        temp_thumbnail = tempfile.NamedTemporaryFile(delete=False, suffix='.jpg')
        temp_thumbnail_path = temp_thumbnail.name
        temp_thumbnail.close()

        # S3から動画をダウンロード
        s3_client.download_file(BUCKET_NAME, s3_key, temp_video_path)

        # ffmpegでサムネイル生成（1秒目のフレームを抽出）
        try:
            (
                ffmpeg
                .input(temp_video_path, ss=1)  # 1秒目のフレーム
                .output(temp_thumbnail_path, vframes=1, format='image2', vcodec='mjpeg')
                .overwrite_output()
                .run(quiet=True)
            )
        except ffmpeg.Error as e:
            return {'success': False, 'error': f'FFmpeg error: {str(e)}'}

        # サムネイルをS3にアップロード
        thumbnail_s3_key = f"{user_id}/{content_id}_thumbnail.jpg"
        s3_client.upload_file(
            temp_thumbnail_path,
            BUCKET_NAME,
            thumbnail_s3_key,
            ExtraArgs={'ContentType': 'image/jpeg'}
        )

        return {
            'success': True,
            'thumbnail_s3_key': thumbnail_s3_key
        }

    except Exception as e:
        print(f"Thumbnail generation error: {str(e)}")
        return {'success': False, 'error': str(e)}
    finally:
        # 一時ファイルを削除
        if temp_video_path and os.path.exists(temp_video_path):
            os.remove(temp_video_path)
        if temp_thumbnail_path and os.path.exists(temp_thumbnail_path):
            os.remove(temp_thumbnail_path)

# セッションクッキー設定の調整フラグ（一度だけ実行するため）
_session_cookie_config_adjusted = False

@app.before_request
def adjust_session_cookie_config_on_first_request():
    """
    最初のリクエスト時にapp.debugに基づいてセッションクッキー設定を調整
    """
    global _session_cookie_config_adjusted
    if not _session_cookie_config_adjusted:
        adjust_session_cookie_config()
        _session_cookie_config_adjusted = True

@app.before_request
def reject_http():
    """
    HTTPリクエストを拒否（HTTPSのみ許可）
    開発環境では無効化され、本番環境またはFORCE_HTTPS環境変数が設定されている場合のみ有効
    
    開発環境の判定方法：
    - app.debug == True (Flask起動時に設定)
    - FLASK_DEBUG環境変数が設定されている
    - app.config.get('DEBUG') == True
    """
    # 開発環境（デバッグモード）ではHTTP拒否を無効化
    # 複数の方法で開発環境を判定（より確実にするため）
    is_development = (
        app.debug or 
        FLASK_DEBUG or 
        app.config.get('DEBUG', False)
    )
    
    if is_development and not FORCE_HTTPS:
        return
    
    # /healthエンドポイントは常に許可
    if request.path == '/health':
        return
    
    # プロキシ経由の場合、X-Forwarded-Protoヘッダーを確認
    # プロキシが正しく設定されていれば、X-Forwarded-Proto: httpsが設定される
    forwarded_proto = request.headers.get('X-Forwarded-Proto', '').lower()
    is_secure = request.is_secure or forwarded_proto == 'https'
    
    # HTTPリクエスト（かつHTTPSに転送されていない）を拒否
    if request.scheme == 'http' and not is_secure:
        return jsonify({'error': 'HTTPS required'}), 403

@app.after_request
def add_security_headers(response):
    """セキュリティヘッダーを追加"""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    # CSP: connect-srcにS3ドメインを追加（リージョン別に列挙）
    # us-east-1はデフォルト形式（*.s3.amazonaws.com）
    # その他のリージョンはリージョン指定形式（*.s3.{region}.amazonaws.com）
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "img-src 'self' data: https:; "
        "script-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "connect-src 'self' "
        "https://*.s3.amazonaws.com "
        "https://*.s3.us-west-2.amazonaws.com; "
        "media-src 'self' "
        "https://*.s3.amazonaws.com "
        "https://*.s3.us-west-2.amazonaws.com;"
    )
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    return response

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/health')
def health():
    return jsonify({'status': 'healthy'}), 200

@app.route('/api/register', methods=['POST'])
def register():
    """ユーザー登録"""
    try:
        data = request.get_json()
        username = data.get('username', '').strip()
        password = data.get('password', '')
        # emailはオプションで、Noneまたは空文字列の可能性がある
        email_value = data.get('email')
        email = email_value.strip() if email_value and isinstance(email_value, str) else None
        
        # バリデーション
        username_valid, username_error = validate_username(username)
        if not username_valid:
            return jsonify({'error': username_error}), 400
        
        password_valid, password_error, password_warning = validate_password(password)
        if not password_valid:
            return jsonify({'error': password_error}), 400
        
        # ユーザー名の重複チェック
        response = users_table.scan(
            FilterExpression='username = :un',
            ExpressionAttributeValues={':un': username}
        )
        if response['Items']:
            return jsonify({'error': 'Username already exists'}), 400
        
        # ユーザー作成
        user_id = str(uuid.uuid4())
        password_hash = hash_password(password)
        created_at = datetime.utcnow().isoformat()
        
        users_table.put_item(Item={
            'user_id': user_id,
            'username': username,
            'password_hash': password_hash,
            'email': email,
            'created_at': created_at
        })
        
        # セッションに保存（永続化）
        session.permanent = True
        session['user_id'] = user_id
        session['username'] = username
        
        response_data = {
            'user_id': user_id,
            'username': username
        }
        
        # パスワードの警告メッセージがある場合はレスポンスに含める
        if password_warning:
            response_data['warning'] = password_warning
        
        return jsonify(response_data), 201
        
    except Exception as e:
        print(f"Registration error: {str(e)}")
        return jsonify({'error': 'Registration failed'}), 500

@app.route('/api/login', methods=['POST'])
def login():
    """ログイン"""
    try:
        data = request.get_json()
        username = data.get('username', '').strip()
        password = data.get('password', '')
        
        if not username or not password:
            return jsonify({'error': 'Username and password are required'}), 400
        
        # DynamoDBからユーザー情報を取得
        response = users_table.scan(
            FilterExpression='username = :un',
            ExpressionAttributeValues={':un': username}
        )
        
        if not response['Items']:
            return jsonify({'error': 'Invalid username or password'}), 401
        
        user = response['Items'][0]
        
        # パスワード検証
        if not verify_password(password, user['password_hash']):
            return jsonify({'error': 'Invalid username or password'}), 401
        
        # セッションに保存（永続化）
        session.permanent = True
        session['user_id'] = user['user_id']
        session['username'] = user['username']
        
        return jsonify({
            'user_id': user['user_id'],
            'username': user['username']
        }), 200
        
    except Exception as e:
        print(f"Login error: {str(e)}")
        return jsonify({'error': 'Login failed'}), 500

@app.route('/api/logout', methods=['POST'])
def logout():
    """ログアウト"""
    session.clear()
    return jsonify({'status': 'success'}), 200

@app.route('/api/me', methods=['GET'])
def get_current_user():
    """現在のユーザー情報取得"""
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    # usernameが存在しない場合に備えて安全にアクセス
    username = session.get('username')
    if not username:
        # usernameが存在しない場合は認証エラーとして扱う
        return jsonify({'error': 'Not authenticated'}), 401
    
    return jsonify({
        'user_id': session['user_id'],
        'username': username
    }), 200

@app.route('/api/users/me', methods=['DELETE'])
@require_auth
def delete_user():
    """ユーザーアカウント削除（全コンテンツも削除）"""
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({'error': 'Not authenticated'}), 401
    
    errors = []
    
    try:
        # ユーザーの全コンテンツを取得（ページネーション対応）
        all_contents = []
        last_evaluated_key = None
        
        while True:
            query_params = {
                'IndexName': 'user-contents-index',
                'KeyConditionExpression': 'user_id = :uid',
                'ExpressionAttributeValues': {':uid': user_id}
            }
            
            if last_evaluated_key:
                query_params['ExclusiveStartKey'] = last_evaluated_key
            
            response = contents_table.query(**query_params)
            all_contents.extend(response['Items'])
            
            # 次のページがあるかチェック
            last_evaluated_key = response.get('LastEvaluatedKey')
            if not last_evaluated_key:
                break
        
        # 各コンテンツのS3オブジェクトとDynamoDBメタデータを削除
        # エラーが発生しても可能な限りすべての削除を試行する
        s3_errors = []
        db_errors = []
        
        for content in all_contents:
            s3_key = content.get('s3_key')
            if s3_key:
                try:
                    s3_client.delete_object(Bucket=BUCKET_NAME, Key=s3_key)
                except Exception as s3_error:
                    s3_errors.append(f"S3 deletion failed for {s3_key}: {str(s3_error)}")
                    print(f"Error: S3 object deletion failed for {s3_key}: {s3_error}")
            
            # DynamoDBからメタデータを削除
            try:
                contents_table.delete_item(
                    Key={
                        'content_id': content['content_id'],
                        'upload_date': content['upload_date']
                    }
                )
            except Exception as db_error:
                db_errors.append(f"DynamoDB content deletion failed for {content.get('content_id')}: {str(db_error)}")
                print(f"Error: DynamoDB content deletion failed for {content.get('content_id')}: {db_error}")
        
        # ユーザーをDynamoDBから削除（コンテンツ削除のエラーがあっても実行）
        # これにより、部分的に削除された状態でユーザーレコードが残ることを防ぐ
        user_deletion_error = None
        user_deletion_succeeded = False
        try:
            users_table.delete_item(
                Key={'user_id': user_id}
            )
            user_deletion_succeeded = True
        except Exception as db_error:
            user_deletion_error = f"DynamoDB user deletion failed for {user_id}: {str(db_error)}"
            print(f"Error: {user_deletion_error}")
        
        # エラーを収集
        if s3_errors:
            errors.extend(s3_errors)
        if db_errors:
            errors.extend(db_errors)
        if user_deletion_error:
            errors.append(user_deletion_error)
        
        # ユーザーレコードの削除が成功した場合のみセッションをクリア
        # これにより、削除が失敗した場合でもクライアントは再試行できる
        if user_deletion_succeeded:
            session.clear()
        
        # エラーが発生した場合は、詳細を含むエラーレスポンスを返す
        if errors:
            # ユーザーレコードの削除が失敗した場合は、セッションを保持してエラーを返す
            if user_deletion_error:
                return jsonify({
                    'error': 'User deletion failed',
                    'details': errors,
                    'note': 'User record deletion failed. Session preserved for retry. Some content may have been deleted.'
                }), 500
            else:
                # コンテンツ削除のエラーのみ（ユーザーレコードは削除済み、セッションもクリア済み）
                # セッションがクリアされているため、401を返してフロントエンドにログアウトを促す
                return jsonify({
                    'error': 'User deletion completed with some content deletion errors',
                    'details': errors,
                    'note': 'User record deleted and session cleared, but some content may remain. Please contact support.',
                    'session_cleared': True
                }), 401
        
        # すべて成功した場合
        return jsonify({'status': 'success'}), 200
        
    except Exception as e:
        error_msg = f"User deletion error: {str(e)}"
        print(f"Error: {error_msg}")
        return jsonify({'error': 'User deletion failed', 'details': [error_msg]}), 500

@app.route('/api/presigned-url', methods=['POST'])
@require_auth
def generate_presigned_url():
    """署名付きURL生成"""
    data = request.get_json()
    filename = data.get('filename')
    content_type = data.get('contentType')
    user_id = session['user_id']  # セッションから取得
    
    # ファイル拡張子取得
    file_extension = filename.rsplit('.', 1)[1].lower() if '.' in filename else 'bin'
    content_id = str(uuid.uuid4())
    s3_key = f"{user_id}/{content_id}.{file_extension}"
    
    # 署名付きURL生成
    url = s3_client.generate_presigned_url(
        'put_object',
        Params={
            'Bucket': BUCKET_NAME,
            'Key': s3_key,
            'ContentType': content_type
        },
        ExpiresIn=3600
    )
    
    return jsonify({
        'url': url,
        's3_key': s3_key,
        'content_id': content_id
    })

@app.route('/api/register-content', methods=['POST'])
@require_auth
def register_content():
    """メタデータ登録"""
    data = request.get_json()
    user_id = session['user_id']  # セッションから取得
    
    # 必須フィールドのバリデーション
    required_fields = ['filename', 'content_id', 's3_key', 'content_type', 'file_size']
    missing_fields = [field for field in required_fields if field not in data or data[field] is None]
    if missing_fields:
        return jsonify({'error': f'Missing required fields: {", ".join(missing_fields)}'}), 400
    
    filename = data['filename']
    s3_key = data['s3_key']
    
    upload_date = datetime.utcnow().isoformat()
    item = {
        'content_id': data['content_id'],
        'upload_date': upload_date,
        'user_id': user_id,
        'filename': data['filename'],
        's3_key': data['s3_key'],
        'content_type': data['content_type'],
        'file_size': data['file_size'],
        'compressed': False
    }
    
    # 重複チェックと挿入をアトミックに実行
    # 早期検出のため、GSIで重複をチェック（非アトミックだが、ほとんどのケースで有効）
    response = contents_table.query(
        IndexName='user-contents-index',
        KeyConditionExpression='user_id = :uid',
        FilterExpression='filename = :fn',
        ExpressionAttributeValues={
            ':uid': user_id,
            ':fn': filename
        }
    )
    
    if response['Items']:
        # 重複している場合は、既にアップロードされたS3オブジェクトを削除してから409 Conflictを返す
        try:
            s3_client.delete_object(Bucket=BUCKET_NAME, Key=s3_key)
        except Exception as s3_error:
            # S3削除が失敗してもログに記録して続行（孤立オブジェクトはライフサイクルポリシーで後から削除される）
            print(f"Warning: Failed to delete orphaned S3 object {s3_key} after duplicate detection: {s3_error}")
        
        return jsonify({'error': 'File with the same name already exists'}), 409
    
    # アトミックな挿入: content_idが存在しないことを条件として挿入
    # これにより、同じcontent_idでの重複挿入を防ぐ
    # 注意: filenameの重複はGSIチェックで検出しているが、完全なアトミック性は保証されない
    # （スキーマ上、filenameは主キーではないため、ConditionExpressionで直接チェックできない）
    from boto3.dynamodb.conditions import Attr
    try:
        contents_table.put_item(
            Item=item,
            ConditionExpression=Attr('content_id').not_exists()
        )
    except ClientError as e:
        error_code = e.response.get('Error', {}).get('Code', '')
        if error_code == 'ConditionalCheckFailedException':
            # content_idが既に存在する場合（理論的には発生しないが、念のため）
            try:
                s3_client.delete_object(Bucket=BUCKET_NAME, Key=s3_key)
            except Exception as s3_error:
                print(f"Warning: Failed to delete orphaned S3 object {s3_key} after conditional check failure: {s3_error}")
            return jsonify({'error': 'Content with the same ID already exists'}), 409
        else:
            # その他のエラー
            raise
    
    # レースコンディション対策: 挿入後に再度重複チェックを実行
    # 挿入直後に同じファイル名のアイテムが複数存在するか確認
    # もし重複が見つかった場合、後から挿入した方（現在のアイテム）を削除
    post_insert_check = contents_table.query(
        IndexName='user-contents-index',
        KeyConditionExpression='user_id = :uid',
        FilterExpression='filename = :fn',
        ExpressionAttributeValues={
            ':uid': user_id,
            ':fn': filename
        }
    )
    
    # 同じファイル名のアイテムが2つ以上存在する場合（重複が発生した場合）
    if len(post_insert_check['Items']) > 1:
        # 現在のアイテム（最後に挿入されたもの）を削除
        # upload_dateでソートして、最新のものを削除
        items_sorted = sorted(post_insert_check['Items'], key=lambda x: x['upload_date'], reverse=True)
        if items_sorted[0]['content_id'] == data['content_id']:
            # 現在のアイテムが最新の場合、削除
            try:
                contents_table.delete_item(
                    Key={
                        'content_id': data['content_id'],
                        'upload_date': upload_date
                    }
                )
                # S3オブジェクトも削除
                try:
                    s3_client.delete_object(Bucket=BUCKET_NAME, Key=s3_key)
                except Exception as s3_error:
                    print(f"Warning: Failed to delete orphaned S3 object {s3_key} after duplicate detection: {s3_error}")
                
                return jsonify({'error': 'File with the same name already exists'}), 409
            except Exception as delete_error:
                # 削除に失敗した場合はログに記録（既に挿入されているため）
                print(f"Warning: Failed to delete duplicate item {data['content_id']}: {delete_error}")
                # エラーを返すが、データは残る（手動で修正が必要）
                return jsonify({
                    'error': 'File with the same name already exists',
                    'note': 'Duplicate detected after insertion. Manual cleanup may be required.'
                }), 409
    
    # 動画の場合、サムネイル生成を試行
    content_type = data['content_type']
    result = {'status': 'success', 'content_id': data['content_id']}
    
    if content_type.startswith('video/'):
        thumbnail_result = generate_video_thumbnail(
            data['content_id'],
            s3_key,
            user_id
        )
        if thumbnail_result.get('success'):
            # サムネイル生成成功時、DynamoDBにthumbnail_s3_keyを追加
            try:
                contents_table.update_item(
                    Key={
                        'content_id': data['content_id'],
                        'upload_date': upload_date
                    },
                    UpdateExpression='SET thumbnail_s3_key = :tsk',
                    ExpressionAttributeValues={
                        ':tsk': thumbnail_result['thumbnail_s3_key']
                    }
                )
                result['thumbnail_s3_key'] = thumbnail_result['thumbnail_s3_key']
            except ClientError as e:
                # DynamoDB更新失敗時はログに記録するが、アップロード自体は成功とする
                # サムネイルはS3に存在するが、メタデータが更新されていない状態
                error_code = e.response.get('Error', {}).get('Code', '')
                print(f"Warning: Failed to update thumbnail metadata for {data['content_id']}: {error_code} - {str(e)}")
                result['thumbnail_metadata_update_error'] = f'Thumbnail generated but metadata update failed: {error_code}'
            except Exception as e:
                # 予期しない例外もキャッチ
                print(f"Warning: Unexpected error updating thumbnail metadata for {data['content_id']}: {str(e)}")
                result['thumbnail_metadata_update_error'] = 'Thumbnail generated but metadata update failed'
        else:
            # サムネイル生成失敗時はログに記録するが、アップロード自体は成功とする
            print(f"Warning: Thumbnail generation failed for {data['content_id']}: {thumbnail_result.get('error')}")
            result['thumbnail_generation_error'] = thumbnail_result.get('error', 'Unknown error')
    
    # 自動圧縮が有効な場合、圧縮処理を実行
    auto_compress = data.get('auto_compress', False)
    
    if auto_compress:
        compression_result = perform_compression(
            data['content_id'],
            data['s3_key'],
            data['content_type'],
            upload_date
        )
        if compression_result.get('success'):
            result['compressed'] = True
            result['original_size'] = compression_result['original_size']
            result['compressed_size'] = compression_result['compressed_size']
        else:
            result['compression_error'] = compression_result.get('error', 'Unknown error')
    
    return jsonify(result)

@app.route('/api/contents', methods=['GET'])
@require_auth
def get_contents():
    """コンテンツ一覧取得"""
    user_id = session['user_id']  # セッションから取得
    
    response = contents_table.query(
        IndexName='user-contents-index',
        KeyConditionExpression='user_id = :uid',
        ExpressionAttributeValues={':uid': user_id},
        ScanIndexForward=False
    )
    
    contents = response['Items']
    current_time = datetime.utcnow()
    
    # S3の署名付きURLを生成（キャッシュを活用、ロック保護）
    for content in contents:
        s3_key = content['s3_key']
        cache_key = f"{user_id}:{s3_key}"
        
        # キャッシュをチェック（ロック保護）
        with _url_cache_lock:
            if cache_key in _url_cache:
                cached_url, cached_time = _url_cache[cache_key]
                if current_time - cached_time < _url_cache_ttl:
                    content['url'] = cached_url
                else:
                    # キャッシュが期限切れの場合は再生成
                    del _url_cache[cache_key]
                    content['url'] = s3_client.generate_presigned_url(
                        'get_object',
                        Params={'Bucket': BUCKET_NAME, 'Key': s3_key},
                        ExpiresIn=3600
                    )
                    _url_cache[cache_key] = (content['url'], current_time)
            else:
                # キャッシュがない場合は新規生成
                content['url'] = s3_client.generate_presigned_url(
                    'get_object',
                    Params={'Bucket': BUCKET_NAME, 'Key': s3_key},
                    ExpiresIn=3600
                )
                _url_cache[cache_key] = (content['url'], current_time)
        
        # サムネイルも同様に処理（ロック保護）
        if 'thumbnail_s3_key' in content:
            thumbnail_cache_key = f"{user_id}:{content['thumbnail_s3_key']}"
            with _url_cache_lock:
                if thumbnail_cache_key in _url_cache:
                    cached_url, cached_time = _url_cache[thumbnail_cache_key]
                    if current_time - cached_time < _url_cache_ttl:
                        content['thumbnail_url'] = cached_url
                    else:
                        del _url_cache[thumbnail_cache_key]
                        content['thumbnail_url'] = s3_client.generate_presigned_url(
                            'get_object',
                            Params={'Bucket': BUCKET_NAME, 'Key': content['thumbnail_s3_key']},
                            ExpiresIn=3600
                        )
                        _url_cache[thumbnail_cache_key] = (content['thumbnail_url'], current_time)
                else:
                    content['thumbnail_url'] = s3_client.generate_presigned_url(
                        'get_object',
                        Params={'Bucket': BUCKET_NAME, 'Key': content['thumbnail_s3_key']},
                        ExpiresIn=3600
                    )
                    _url_cache[thumbnail_cache_key] = (content['thumbnail_url'], current_time)
    
    return jsonify({'contents': contents})

@app.route('/api/contents/<content_id>', methods=['DELETE'])
@require_auth
def delete_content(content_id):
    """コンテンツ削除（所有者チェックあり）"""
    try:
        user_id = session['user_id']  # セッションから取得

        # DynamoDBからメタデータを取得（content_id と user_id でフィルタ）
        response = contents_table.scan(
            FilterExpression='content_id = :cid AND user_id = :uid',
            ExpressionAttributeValues={
                ':cid': content_id,
                ':uid': user_id
            }
        )

        if not response['Items']:
            # content_id は存在するが別ユーザーのものである可能性も含めて Not Found と扱う
            return jsonify({'error': 'Content not found'}), 404

        item = response['Items'][0]
        s3_key = item['s3_key']
        upload_date = item['upload_date']
        
        # サムネイルが存在する場合、サムネイルも削除
        thumbnail_s3_key = item.get('thumbnail_s3_key')
        if thumbnail_s3_key:
            try:
                s3_client.delete_object(Bucket=BUCKET_NAME, Key=thumbnail_s3_key)
            except Exception as thumbnail_error:
                print(f"Warning: Failed to delete thumbnail {thumbnail_s3_key}: {thumbnail_error}")

        # まずDynamoDBからメタデータを削除（順序を逆にして、DynamoDB削除が失敗した場合はS3削除を実行しない）
        contents_table.delete_item(
            Key={
                'content_id': content_id,
                'upload_date': upload_date
            }
        )

        # DynamoDB削除が成功したら、S3からオブジェクトを削除
        # 注意: S3削除が失敗しても、メタデータは既に削除されているため、
        # 孤立したS3オブジェクトはライフサイクルポリシーで後から削除される
        try:
            s3_client.delete_object(Bucket=BUCKET_NAME, Key=s3_key)
        except Exception as s3_error:
            # S3削除が失敗しても、メタデータは既に削除されているため成功として扱う
            # ログに記録することを推奨（本番環境では）
            print(f"Warning: S3 object deletion failed for {s3_key}: {s3_error}")

        return jsonify({'status': 'success'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/contents/<content_id>/download', methods=['GET'])
@require_auth
def download_content(content_id):
    """ダウンロード用署名付きURL生成（所有者チェックあり）"""
    try:
        user_id = session['user_id']  # セッションから取得

        # DynamoDBからメタデータを取得（content_id と user_id でフィルタ）
        response = contents_table.scan(
            FilterExpression='content_id = :cid AND user_id = :uid',
            ExpressionAttributeValues={
                ':cid': content_id,
                ':uid': user_id
            }
        )

        if not response['Items']:
            return jsonify({'error': 'Content not found'}), 404

        item = response['Items'][0]
        s3_key = item['s3_key']
        filename = sanitize_filename(item.get('filename'))

        # ダウンロード用署名付きURLを生成（ContentDispositionヘッダー付き）
        url = s3_client.generate_presigned_url(
            'get_object',
            Params={
                'Bucket': BUCKET_NAME,
                'Key': s3_key,
                'ResponseContentDisposition': f'attachment; filename="{filename}"'
            },
            ExpiresIn=3600
        )

        return jsonify({
            'url': url,
            'filename': filename
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/contents/<content_id>/compress', methods=['POST'])
@require_auth
def compress_content(content_id):
    """コンテンツ圧縮（所有者チェックあり）"""
    temp_input_path = None
    temp_output_path = None
    
    try:
        user_id = session['user_id']  # セッションから取得

        # DynamoDBからメタデータを取得（content_id と user_id でフィルタ）
        response = contents_table.scan(
            FilterExpression='content_id = :cid AND user_id = :uid',
            ExpressionAttributeValues={
                ':cid': content_id,
                ':uid': user_id
            }
        )

        if not response['Items']:
            return jsonify({'error': 'Content not found'}), 404

        item = response['Items'][0]
        
        # 既に圧縮済みの場合はエラー
        if item.get('compressed', False):
            return jsonify({'error': 'Content is already compressed'}), 400

        s3_key = item['s3_key']
        content_type = item.get('content_type', '')
        upload_date = item['upload_date']

        # 圧縮処理を実行
        compression_result = perform_compression(content_id, s3_key, content_type, upload_date)
        
        if not compression_result.get('success'):
            return jsonify({'error': compression_result.get('error', 'Compression failed')}), 500

        return jsonify({
            'status': 'success',
            'original_size': compression_result['original_size'],
            'compressed_size': compression_result['compressed_size']
        }), 200

    except Exception as e:
        print(f"Compression error: {str(e)}")
        return jsonify({'error': str(e)}), 500

def cleanup_temp_files_after_delay(zip_path, dir_path, max_retries=30, retry_interval=2):
    """
    バックグラウンドスレッドで一時ファイルを削除
    ファイルが削除可能になるまでリトライする（最大60秒: 30回×2秒）
    """
    def cleanup():
        retries = 0
        while retries < max_retries:
            time.sleep(retry_interval)  # 各リトライの間隔
            try:
                # ファイルが存在し、削除可能かチェック
                if zip_path and os.path.exists(zip_path):
                    # Windowsでは、ファイルが開いている場合PermissionErrorが発生
                    # 削除を試みて成功すれば、ファイルは閉じられている
                    try:
                        os.remove(zip_path)
                    except PermissionError:
                        # ファイルがまだ開いている場合はリトライ
                        retries += 1
                        continue
                    except FileNotFoundError:
                        # 既に削除されている場合は成功
                        pass
                
                # ディレクトリの削除
                if dir_path and os.path.exists(dir_path):
                    try:
                        for file in os.listdir(dir_path):
                            file_path = os.path.join(dir_path, file)
                            if os.path.isfile(file_path):
                                try:
                                    os.remove(file_path)
                                except (PermissionError, FileNotFoundError):
                                    pass
                        os.rmdir(dir_path)
                    except (OSError, PermissionError):
                        # ディレクトリが空でない、または削除できない場合はリトライ
                        retries += 1
                        continue
                
                # すべての削除が成功したら終了
                break
            except Exception as e:
                retries += 1
                if retries >= max_retries:
                    print(f"Cleanup error after {max_retries} retries: {str(e)}")
                continue
        
        if retries >= max_retries:
            print(f"Warning: Could not delete temporary files after {max_retries} retries")
    
    # バックグラウンドスレッドで実行（daemon=Trueでメインスレッド終了時に自動終了）
    thread = threading.Thread(target=cleanup, daemon=True)
    thread.start()

@app.route('/api/contents/batch-download', methods=['POST'])
@require_auth
def batch_download_contents():
    """一括ダウンロード（Zip生成）"""
    temp_zip_path = None
    temp_dir = None
    
    try:
        user_id = session['user_id']  # セッションから取得
        data = request.get_json()
        if data is None:
            return jsonify({'error': 'Invalid JSON or missing Content-Type: application/json'}), 400
        content_ids = data.get('content_ids', [])
        
        if not content_ids:
            return jsonify({'error': 'No content IDs provided'}), 400
        
        if not isinstance(content_ids, list):
            return jsonify({'error': 'content_ids must be a list'}), 400
        
        # 一時ディレクトリを作成
        temp_dir = tempfile.mkdtemp()
        temp_zip_path = os.path.join(temp_dir, 'download.zip')
        
        # Zipファイルを作成
        with zipfile.ZipFile(temp_zip_path, 'w', zipfile.ZIP_DEFLATED) as zip_file:
            added_count = 0
            skipped_count = 0
            
            for content_id in content_ids:
                try:
                    # DynamoDBからメタデータを取得（所有者チェック）
                    response = contents_table.scan(
                        FilterExpression='content_id = :cid AND user_id = :uid',
                        ExpressionAttributeValues={
                            ':cid': content_id,
                            ':uid': user_id
                        }
                    )
                    
                    if not response['Items']:
                        # 所有者でない、または存在しないコンテンツはスキップ
                        skipped_count += 1
                        print(f"Warning: Content {content_id} not found or not owned by user {user_id}")
                        continue
                    
                    item = response['Items'][0]
                    s3_key = item['s3_key']
                    filename = sanitize_filename(item.get('filename', 'unknown'))
                    
                    # S3からファイルをダウンロード
                    temp_file_path = os.path.join(temp_dir, f"{content_id}_{filename}")
                    try:
                        s3_client.download_file(BUCKET_NAME, s3_key, temp_file_path)
                        
                        # Zipファイルに追加（重複を避けるため、完全なcontent_idを含む一意なファイル名を使用）
                        # ファイル名と拡張子を分離
                        name, ext = os.path.splitext(filename)
                        # 完全なcontent_idを使用して一意化（衝突を完全に回避）
                        unique_filename = f"{name}_{content_id}{ext}"
                        zip_file.write(temp_file_path, unique_filename)
                        added_count += 1
                        
                        # 一時ファイルを削除
                        os.remove(temp_file_path)
                    except Exception as download_error:
                        print(f"Error downloading {s3_key}: {str(download_error)}")
                        skipped_count += 1
                        # 一時ファイルが存在する場合は削除
                        if os.path.exists(temp_file_path):
                            os.remove(temp_file_path)
                        continue
                        
                except Exception as e:
                    print(f"Error processing content {content_id}: {str(e)}")
                    skipped_count += 1
                    continue
        
        if added_count == 0:
            # 一時ファイルを削除
            if temp_zip_path and os.path.exists(temp_zip_path):
                os.remove(temp_zip_path)
            if temp_dir and os.path.exists(temp_dir):
                try:
                    for file in os.listdir(temp_dir):
                        file_path = os.path.join(temp_dir, file)
                        if os.path.isfile(file_path):
                            os.remove(file_path)
                    os.rmdir(temp_dir)
                except Exception:
                    pass
            return jsonify({'error': 'No files could be downloaded'}), 400
        
        # Zipファイルをレスポンスとして返送
        # send_file()の後にクリーンアップを開始することで、
        # ファイルが確実に開かれた後に削除処理が開始される（レースコンディションを回避）
        response = send_file(
            temp_zip_path,
            mimetype='application/zip',
            as_attachment=True,
            download_name='download.zip'
        )
        
        # バックグラウンドスレッドでファイル送信完了後に一時ファイルを削除
        # ファイルが削除可能になるまでリトライすることで、
        # WindowsでのPermissionErrorや不完全なダウンロードを防ぐ
        cleanup_temp_files_after_delay(temp_zip_path, temp_dir)
        
        return response
        
    except Exception as e:
        print(f"Batch download error: {str(e)}")
        # エラー時も一時ファイルをクリーンアップ
        try:
            if temp_zip_path and os.path.exists(temp_zip_path):
                os.remove(temp_zip_path)
            if temp_dir and os.path.exists(temp_dir):
                for file in os.listdir(temp_dir):
                    file_path = os.path.join(temp_dir, file)
                    if os.path.isfile(file_path):
                        os.remove(file_path)
                os.rmdir(temp_dir)
        except Exception:
            pass
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000, debug=True)
