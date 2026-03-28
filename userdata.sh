#!/bin/bash
# Photo Service EC2 User Data Script
# このスクリプトはEC2インスタンス起動時に自動実行されます

set -e  # エラーが発生したら停止

# ログ出力用
exec > >(tee /var/log/user-data.log|logger -t user-data -s 2>/dev/console) 2>&1
echo "=== User Data Script Started: $(date) ==="

# ============================================
# 環境変数の設定（Launch Templateのパラメータから取得可能）
# ============================================
# 環境変数が設定されていない場合はデフォルト値を使用
# Launch Templateで環境変数を設定する場合:
#   - User Dataの先頭に export NLB_DOMAIN="..." を追加
#   - または、EC2インスタンスの環境変数として設定

# デフォルトはダミーです。運用前に書き換えるか、ユーザデータ先頭で export してください（README 参照）。
NLB_DOMAIN="${NLB_DOMAIN:-your-nlb-dns.elb.us-east-1.amazonaws.com}"
S3_BUCKET_NAME="${S3_BUCKET_NAME:-your-s3-bucket-name}"
AWS_REGION="${AWS_REGION:-us-east-1}"

echo "=== Configuration ==="
echo "NLB_DOMAIN: ${NLB_DOMAIN}"
echo "S3_BUCKET_NAME: ${S3_BUCKET_NAME}"
echo "AWS_REGION: ${AWS_REGION}"

# 1. システムアップデート
echo "=== Updating system packages ==="
yum update -y

# 2. 必要なパッケージのインストール
echo "=== Installing required packages ==="
yum install -y \
    python3.11 \
    python3.11-devel \
    python3.11-pip \
    git \
    nginx \
    openssl \
    wget \
    tar

# 3. ffmpegのインストール（静的ビルド）
echo "=== Installing ffmpeg ==="
mkdir -p ~/ffmpeg && cd ~/ffmpeg
wget https://johnvansickle.com/ffmpeg/releases/ffmpeg-release-amd64-static.tar.xz
tar -xf ffmpeg-release-amd64-static.tar.xz
cd ffmpeg-*-static
sudo cp ffmpeg /usr/local/bin/
sudo cp ffprobe /usr/local/bin/
sudo chmod +x /usr/local/bin/ffmpeg
sudo chmod +x /usr/local/bin/ffprobe
cd ~
rm -rf ~/ffmpeg

# 4. uvのインストール（開発用）
echo "=== Installing uv ==="
curl -LsSf https://astral.sh/uv/install.sh | sh
# PATHに追加（このセッション用）
export PATH="$HOME/.local/bin:$PATH"

# 5. Pythonパッケージのインストール
echo "=== Installing Python packages ==="
pip3.11 install --upgrade pip
pip3.11 install \
    Flask==3.1.2 \
    boto3==1.42.28 \
    Pillow==12.1.0 \
    ffmpeg-python==0.2.0 \
    gunicorn==23.0.0 \
    python-dotenv==1.2.1 \
    bcrypt==4.1.2

# 6. アプリケーションディレクトリの作成
echo "=== Creating application directory ==="
mkdir -p /opt/photo-service

# 7. アプリケーションコードをGitHubから取得
echo "=== Cloning application from GitHub ==="
git clone https://github.com/YOUR_ACCOUNT/photo-service.git /opt/photo-service
cd /opt/photo-service

# 8. 環境変数ファイルの作成
echo "=== Creating .env file ==="
cat > /opt/photo-service/.env <<EOF
S3_BUCKET_NAME=${S3_BUCKET_NAME}
AWS_REGION=${AWS_REGION}
SECRET_KEY=CHANGE_ME_ON_FIRST_LAUNCH
FLASK_ENV=production
EOF

# SECRET_KEYをランダムに生成
SECRET_KEY=$(openssl rand -hex 32)
sed -i "s/SECRET_KEY=CHANGE_ME_ON_FIRST_LAUNCH/SECRET_KEY=$SECRET_KEY/" /opt/photo-service/.env

# 9. Nginx SSL証明書の作成
echo "=== Creating SSL certificates ==="
echo "Using NLB_DOMAIN: ${NLB_DOMAIN}"
sudo mkdir -p /etc/nginx/ssl
# NLBのドメイン名を含む証明書を作成（環境変数から取得）
sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout /etc/nginx/ssl/nginx-selfsigned.key \
    -out /etc/nginx/ssl/nginx-selfsigned.crt \
    -subj "/C=US/ST=State/L=City/O=Organization/CN=${NLB_DOMAIN}" \
    -addext "subjectAltName=DNS:${NLB_DOMAIN},DNS:*.elb.${AWS_REGION}.amazonaws.com,DNS:photo-service"

# 10. Nginx設定ファイルの作成
echo "=== Creating Nginx configuration ==="
sudo tee /etc/nginx/conf.d/photo-service.conf > /dev/null <<'EOF'
# HTTPS (443) でリッスン
server {
    listen 443 ssl;
    http2 on;
    server_name _;

    # SSL証明書
    ssl_certificate /etc/nginx/ssl/nginx-selfsigned.crt;
    ssl_certificate_key /etc/nginx/ssl/nginx-selfsigned.key;

    # SSL設定
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;

    # HTTP Strict Transport Security
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

    # ログ設定
    access_log /var/log/nginx/photo-service_access.log;
    error_log /var/log/nginx/photo-service_error.log;

    # アップロードサイズ制限
    client_max_body_size 100M;

    # Flaskアプリにプロキシ
    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_http_version 1.1;
        
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header X-Forwarded-Host $host;
        proxy_set_header X-Forwarded-Port $server_port;
        
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        
        proxy_redirect off;
    }
}

# HTTP (80) をHTTPS (443) にリダイレクト
server {
    listen 80;
    server_name _;
    return 301 https://$host$request_uri;
}
EOF

# 11. systemdサービスファイルの作成
echo "=== Creating systemd service ==="
sudo tee /etc/systemd/system/photo-service.service > /dev/null <<'EOF'
[Unit]
Description=Photo Service
After=network.target

[Service]
Type=simple
User=ec2-user
WorkingDirectory=/opt/photo-service
Environment="PATH=/usr/local/bin:/usr/bin:/bin"
EnvironmentFile=/opt/photo-service/.env
ExecStart=/usr/local/bin/gunicorn -w 4 -b 0.0.0.0:8000 app:app
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# 12. ファイルの所有権設定
echo "=== Setting file permissions ==="
sudo chown -R ec2-user:ec2-user /opt/photo-service

# 13. systemdのリロードとサービスの有効化
echo "=== Enabling services ==="
sudo systemctl daemon-reload
sudo systemctl enable photo-service
sudo systemctl enable nginx

# 14. サービスの起動
echo "=== Starting services ==="
sudo systemctl start photo-service
sudo systemctl start nginx

# 15. サービスの状態確認
echo "=== Checking service status ==="
sleep 5
sudo systemctl status photo-service --no-pager || true
sudo systemctl status nginx --no-pager || true

echo "=== User Data Script Completed: $(date) ==="