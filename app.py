from flask import Flask, request, jsonify, render_template, session
from functools import wraps
import boto3
import uuid
from datetime import datetime, timedelta
import os
import tempfile
from dotenv import load_dotenv
from PIL import Image
import ffmpeg
import bcrypt

# 環境変数を読み込み
load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')
# セッションクッキーのセキュリティ設定
# NLB + Nginx HTTPS終端構成では常にHTTPS前提
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = True  # HTTPS環境では常にTrue
app.config['SESSION_COOKIE_SAMESITE'] = 'None'  # fetch APIでクッキーを送信するため（Secure=Trueが必須）
# セッションの永続化設定
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=7)

# AWS設定（Learner Labでは us-east-1 または us-west-2 のみ利用可能）
AWS_REGION = os.environ.get('AWS_REGION', 'us-east-1')
s3_client = boto3.client('s3', region_name=AWS_REGION)
dynamodb = boto3.resource('dynamodb', region_name=AWS_REGION)
BUCKET_NAME = os.environ.get('S3_BUCKET_NAME', 'photo-video-storage-default')
contents_table = dynamodb.Table('contents')
users_table = dynamodb.Table('users')


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
        if not username:
            return jsonify({'error': 'Username is required'}), 400
        if not password:
            return jsonify({'error': 'Password is required'}), 400
        if len(password) < 8:
            return jsonify({'error': 'Password must be at least 8 characters'}), 400
        if len(username) < 3:
            return jsonify({'error': 'Username must be at least 3 characters'}), 400
        
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
        
        return jsonify({
            'user_id': user_id,
            'username': username
        }), 201
        
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
    
    contents_table.put_item(Item=item)
    
    # 自動圧縮が有効な場合、圧縮処理を実行
    auto_compress = data.get('auto_compress', False)
    result = {'status': 'success', 'content_id': data['content_id']}
    
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
    
    # S3の署名付きURLを生成
    for content in contents:
        s3_key = content['s3_key']
        content['url'] = s3_client.generate_presigned_url(
            'get_object',
            Params={'Bucket': BUCKET_NAME, 'Key': s3_key},
            ExpiresIn=3600
        )
    
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

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000, debug=True)
