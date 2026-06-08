Install Docker + Compose for installation of containers automaticly.
Follow this cmd line guide step by step for installation.

sudo apt install -y ca-certificates curl gnupg lsb-release

sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo tee /etc/apt/keyrings/docker.asc > /dev/null
sudo chmod a+r /etc/apt/keyrings/docker.asc

echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu \
  $(. /etc/os-release && echo "${UBUNTU_CODENAME:-$VERSION_CODENAME}") stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

sudo apt update
sudo apt install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

sudo systemctl enable --now docker
sudo usermod -aG docker $USER
newgrp docker

mkdir -p ~/juice-lab/logs
cd ~/juice-lab

tee docker-compose.yml > /dev/null <<'EOF'
services:
  juice-shop:
    image: bkimminich/juice-shop:snapshot
    container_name: juice-shop
    expose:
      - "3000"
    restart: unless-stopped

  nginx:
    image: nginx:alpine
    container_name: juice-nginx
    ports:
      - "8080:80"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf:ro
      - ./logs:/var/log/nginx
    depends_on:
      - juice-shop
    restart: unless-stopped
EOF

tee nginx.conf > /dev/null <<'EOF'
events {}

http {
    log_format threat_hunt '$remote_addr '
                           'xff="$http_x_forwarded_for" '
                           'realip="$http_x_real_ip" '
                           '[$time_local] '
                           '"$request" $status $body_bytes_sent '
                           '"$http_referer" "$http_user_agent" '
                           'rt=$request_time '
                           'urt=$upstream_response_time';

    access_log /var/log/nginx/access.log threat_hunt;
    error_log  /var/log/nginx/error.log warn;

    server {
        listen 80;

        location / {
            proxy_pass http://juice-shop:3000;

            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
        }
    }
}
EOF


docker compose up -d


docker ps