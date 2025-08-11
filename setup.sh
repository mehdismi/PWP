#!/bin/bash
set -e
BASE_DIR=$(pwd)

# Install core packages
sudo apt update
sudo apt install -y python3 python3-pip python3-venv nginx

# Install Node.js if not present
if ! command -v npm &> /dev/null; then
    curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
    sudo apt install -y nodejs
fi

# Install dependencies
sudo apt install -y postgresql postgresql-contrib nmap

# PostgreSQL user/db setup (move to safe dir to avoid permission issues)
cd /tmp
sudo -u postgres psql -c "DO \$\$ BEGIN IF NOT EXISTS (SELECT FROM pg_catalog.pg_user WHERE usename = 'netscan') THEN CREATE USER netscan WITH PASSWORD 'netscan'; END IF; END \$\$;"
sudo -u postgres psql -tAc "SELECT 1 FROM pg_database WHERE datname='netscan'" | grep -q 1 || sudo -u postgres createdb -O netscan netscan
cd "$BASE_DIR"

# Fix project permissions (in case script is run with sudo)
sudo chown -R $USER:$USER "$BASE_DIR"

# Django backend setup
cd "$BASE_DIR/network_scanner"
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
python manage.py makemigrations
python manage.py migrate
nohup python manage.py runserver 0.0.0.0:8000 &
deactivate

# React frontend setup
cd "$BASE_DIR/network_scanner/netscan-frontend"
npm install

# Ensure homepage path is root for proper static linking
if ! grep -q '"homepage"' package.json; then
    sed -i '1s/^/"homepage": "\/",\n/' package.json
fi
npm run build

# Deploy React build to NGINX
sudo mkdir -p /var/www/react-frontend
sudo cp -r build/* /var/www/react-frontend/

# Set permissions for NGINX access
sudo chmod -R o+r /var/www/react-frontend
sudo find /var/www/react-frontend -type d -exec chmod o+rx {} \;

# NGINX configuration
NGINX_CONF="/etc/nginx/sites-available/react-frontend"
sudo bash -c "cat > $NGINX_CONF" <<EOL
server {
    listen 8080;
    server_name _;

    root /var/www/react-frontend;
    index index.html;

    location / {
        try_files \$uri \$uri/ /index.html;
    }

    location /static/ {
        alias /var/www/react-frontend/static/;
        expires 1y;
        add_header Cache-Control \"public\";
    }

    error_page 404 /index.html;
}
EOL

# Enable NGINX config
sudo ln -sf $NGINX_CONF /etc/nginx/sites-enabled/react-frontend
sudo rm -f /etc/nginx/sites-enabled/default
sudo nginx -t && sudo systemctl reload nginx

# Final messages
echo "\n Django API running on: http://<your-ip>:8000"
echo " React frontend served via NGINX: http://<your-ip>:8080"
