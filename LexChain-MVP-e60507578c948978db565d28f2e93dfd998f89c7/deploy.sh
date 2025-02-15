#!/bin/bash

# Build frontend
cd lexchain-newdash/tailwindcss4
npm install
npm run build

# Create necessary directories
sudo mkdir -p /var/www/dashboard.lexchain.net
sudo mkdir -p /var/www/dashboard.lexchain.net/api

# Copy frontend build
sudo cp -r dist/* /var/www/dashboard.lexchain.net/

# Setup Python environment for backend
cd ../../lexchain
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Copy backend files
sudo cp -r * /var/www/dashboard.lexchain.net/api/
sudo cp .env /var/www/dashboard.lexchain.net/api/

# Setup Nginx configuration
sudo bash -c 'cat > /etc/nginx/sites-available/dashboard.lexchain.net' << 'EOL'
server {
    listen 80;
    server_name dashboard.lexchain.net;
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl;
    server_name dashboard.lexchain.net;

    ssl_certificate /etc/letsencrypt/live/dashboard.lexchain.net/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/dashboard.lexchain.net/privkey.pem;

    # Frontend
    location / {
        root /var/www/dashboard.lexchain.net;
        try_files $uri $uri/ /index.html;
        add_header Cache-Control "no-cache, no-store, must-revalidate";
    }

    # Backend API
    location /api/ {
        proxy_pass http://127.0.0.1:5000/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
EOL

# Enable the site
sudo ln -s /etc/nginx/sites-available/dashboard.lexchain.net /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl restart nginx

# Setup SSL with Let's Encrypt
sudo certbot --nginx -d dashboard.lexchain.net

# Setup systemd service for the Flask app
sudo bash -c 'cat > /etc/systemd/system/lexchain.service' << 'EOL'
[Unit]
Description=LexChain Dashboard
After=network.target

[Service]
User=www-data
WorkingDirectory=/var/www/dashboard.lexchain.net/api
Environment="PATH=/var/www/dashboard.lexchain.net/api/venv/bin"
ExecStart=/var/www/dashboard.lexchain.net/api/venv/bin/gunicorn -w 4 -b 127.0.0.1:5000 app1:app

[Install]
WantedBy=multi-user.target
EOL

# Start and enable the service
sudo systemctl start lexchain
sudo systemctl enable lexchain 