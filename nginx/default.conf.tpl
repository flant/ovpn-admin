server {
listen 8088;
server_name 127.0.0.1;

  location / {
    auth_basic           "Pass";
    auth_basic_user_file /etc/nginx/.htpasswd;
    proxy_pass http://${OVPN_ADMIN_IP}:8080;

    # Disable caching of credentials
    add_header Cache-Control "no-store, private, no-cache, must-revalidate, max-age=0";
    add_header Pragma "no-cache";
    add_header Expires "Thu, 01 Jan 1970 00:00:00 GMT";

  }
}
