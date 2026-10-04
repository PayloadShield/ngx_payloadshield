rm -rf ngx_payloadshield-main main.zip  
wget https://github.com/PayloadShield/ngx_payloadshield/archive/refs/heads/main.zip
unzip main.zip
cd nginx-1.28.3
make clear
./configure \
    --with-compat \
    --with-http_ssl_module \
    --with-http_v2_module \
    --add-dynamic-module=/root/setup/ngx_payloadshield-main \
    --with-cc-opt="-D_GNU_SOURCE"
make modules
sudo install -D -m 0644 objs/ngx_http_payloadshield_module.so \
    /usr/lib/nginx/modules/ngx_http_payloadshield_module.so
service nginx restart
