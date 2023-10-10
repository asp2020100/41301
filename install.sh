#!/bin/bash

echo "Domain Name :"
read Domain
echo "Enter UUID 01 :"
read UUID1
echo "Enter UUID 02 :"
read UUID2
echo "Enter UUID 03 :"
read UUID3
echo "Enter IPv6 :"
read IPv6
echo "Enter secretKey :"
read secretKey
echo "Enter Cloud Front Domain :"
read cfdomain
echo "Enter reserved number 1 :"
read r1
echo "Enter reserved number 2 :"
read r2
echo "Enter reserved number 3 :"
read r3

#Update System

sudo su 
sudo apt-get update
sudo apt-get upgrade -y

#install xray

bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install --beta

#install nginx

sudo apt install nginx python3-certbot

#firewall

sudo apt update
sudo apt install firewalld
sudo systemctl enable firewalld
sudo systemctl start firewalld
sudo ufw disable
sudo firewall-cmd --permanent --add-service={http,https} --permanent
sudo systemctl restart firewalld
sudo firewall-cmd --list-all



#Adding a xray config json

rm -rf /usr/local/etc/xray/config.json
cat << EOF > /usr/local/etc/xray/config.json
{
  "log": {
    "loglevel": "none",
    "access": "/var/log/xray/access.log",
    "error": "/var/log/xray/error.log"
  },
  "inbounds": [
    {
      "sniffing": {
        "enabled": true,
        "destOverride": [
          "http",
          "tls",
          "quic"
        ]
      },
      "port": 443,
      "protocol": "vless",
      "settings": {
        "clients": [
          {
            "id": "$UUID1",
            "email": "old-xtls",
            "flow": "xtls-rprx-vision",
            "level": 0
          },
          {
            "id": "$UUID2",
            "email": "new-xtls",
            "flow": "xtls-rprx-vision",
            "level": 0
          },
          {
            "id": "$UUID3",
            "email": "speedforce",
            "flow": "xtls-rprx-vision",
            "level": 0
          }
        ],
        "decryption": "none",
        "fallbacks": [
          {
            "dest": "@trojan-tcp",
            "xver": 2
          }
        ]
      },
      "streamSettings": {
        "network": "tcp",
        "security": "tls",
        "tlsSettings": {
          "minVersion": "1.2",
          "cipherSuites": "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
          "alpn": [
            "http/1.1"
          ],
          "certificates": [
            {
              "ocspStapling": 3600,
              "certificateFile": "/etc/xray/xray.crt",
              "keyFile": "/etc/xray/xray.key"
            }
          ]
        }
      }
    },
    {
      "sniffing": {
        "enabled": true,
        "destOverride": [
          "http",
          "tls",
          "quic"
        ]
      },
      "listen": "@trojan-tcp",
      "protocol": "trojan",
      "settings": {
        "clients": [
          {
            "password": "$UUID1",
            "email": "old-trojan",
            "level": 0
          }
        ],
        "fallbacks": [
          {
            "path": "/trojanws",
            "dest": "@trojanws",
            "xver": 2
          },
          {
            "path": "/websocket",
            "dest": "@websocket",
            "xver": 2
          },
          {
            "dest": "/dev/shm/h1.sock",
            "xver": 2
          }
        ]
      },
      "streamSettings": {
        "network": "tcp",
        "security": "none",
        "tcpSettings": {
          "acceptProxyProtocol": true
        }
      }
    },
    {
      "sniffing": {
        "enabled": true,
        "destOverride": [
          "http",
          "tls",
          "quic"
        ]
      },
      "listen": "@trojanws",
      "protocol": "trojan",
      "settings": {
        "clients": [
          {
            "password": "$UUID1",
            "email": "old-trojanws",
            "level": 0
          },
          {
            "password": "$UUID2",
            "email": "trojanws",
            "level": 0
          }
        ]
      },
      "streamSettings": {
        "network": "ws",
        "security": "none",
        "wsSettings": {
          "acceptProxyProtocol": true,
          "path": "/trojanws"
        }
      }
    },
    {
      "sniffing": {
        "enabled": true,
        "destOverride": [
          "http",
          "tls",
          "quic"
        ]
      },
      "listen": "@websocket",
      "protocol": "vless",
      "settings": {
        "clients": [
          {
            "id": "$UUID1",
            "email": "oldvlessws",
            "level": 0
          },
          {
            "id": "$UUID2",
            "email": "vlessws",
            "level": 0
          },
          {
            "id": "$UUID3",
            "email": "speedforce",
            "level": 0
          }
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "ws",
        "security": "none",
        "wsSettings": {
          "acceptProxyProtocol": true,
          "path": "/websocket"
        }
      }
    }
  ],
  "outbounds": [
    {
      "protocol": "freedom",
      "tag": "direct"
    },
    {
      "protocol": "blackhole",
      "tag": "block"
    },
    {
      "protocol": "wireguard",
      "settings": {
        "secretKey": "$secretKey",
        "address": [
          "172.16.0.2/32",
          "$IPv6/128"
        ],
        "peers": [
          {
            "publicKey": "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=",
            "allowedIPs": [
              "0.0.0.0/0",
              "::/0"
            ],
            "endpoint": "162.159.192.1:2408"
          }
        ],
        "reserved": [
          $r1, 
          $r2, 
          $r3
        ],
        "mtu": 1280
      },
      "tag": "wireguard"
    },
    {
      "protocol": "freedom",
      "settings": {
        "domainStrategy": "UseIPv6"
      },
      "proxySettings": {
        "tag": "wireguard"
      },
      "tag": "warp-IPv6"
    }
  ],
  "routing": {
    "domainStrategy": "AsIs",
    "rules": [
      {
        "type": "field",
        "protocol": [
          "bittorrent"
        ],
        "outboundTag": "block"
      },
      {
        "type": "field",
        "port": "443",
        "network": "udp",
        "outboundTag": "block"
      },
      {
        "type": "field",
        "domain": [
          "geosite:openai",
          "ip.gs",
          "send.ozonedesk.com",
          "dominos.com"
        ],
        "outboundTag": "warp-IPv6"
      },
      {
        "type": "field",
        "user": [
          "speedforce"
        ],
        "outboundTag": "warp-IPv6"
      },
      {
        "type": "field",
        "ip": [
          "geoip:private"
        ],
        "outboundTag": "block"
      }
    ]
  }
}
EOF

#installing BBR

wget -P /tmp https://raw.githubusercontent.com/teddysun/across/master/bbr.sh
chmod +x /tmp/bbr.sh
/tmp/bbr.sh

#nginx config
sudo rm /etc/nginx/sites-enabled/default
rm /etc/nginx/sites-available/fallback
cat << EOF > /etc/nginx/sites-available/fallback   
server {
    listen unix:/dev/shm/h1.sock proxy_protocol default_server;
    set_real_ip_from unix:;
    real_ip_header proxy_protocol;
    server_name _;
    return 400;
}

server {
    listen unix:/dev/shm/h1.sock proxy_protocol; # HTTP/1.1 server monitor process and enable PROXY protocol reception
    set_real_ip_from unix:;
    real_ip_header proxy_protocol;
    server_name $domain;

    location / {
        add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
        root /var/www/fallback_site/html;
        index index.html index.htm;
    }
}
EOF

sudo ln -s /etc/nginx/sites-available/fallback /etc/nginx/sites-enabled/

#SSL
systemctl restart nginx
sudo mkdir /etc/xray
sudo certbot certonly --standalone -d $domain
sudo nano "/etc/letsencrypt/renewal/$domain.conf"
echo "post_hook = cp /etc/letsencrypt/live/$domain/fullchain.pem /etc/xray/xray.crt && cp /etc/letsencrypt/live/$domain/privkey.pem /etc/xray/xray.key && chmod 666 /etc/xray/xray.key && service xray restart" | sudo tee -a "/etc/letsencrypt/renewal/$domain.conf"
sudo nano -O "/etc/letsencrypt/renewal/$domain.conf"
echo "Script executed successfully!"
sleep 10
sudo certbot renew --force-renewal


#fallback_site

sudo mkdir -p /var/www/fallback_site/html
sudo chmod -R 755 /var/www/fallback_site/html
rm /var/www/fallback_site/html/index.html
wget -P /var/www/fallback_site/html https://raw.githubusercontent.com/speedforce-lk/nekobox/main/index.html


#install warp
#curl -sLo warp-reg https://github.com/badafans/warp-reg/releases/download/v1.0/main-linux-amd64 && chmod +x warp-reg && ./warp-reg && rm warp-reg


#Config for App

cat << EOF > /home/ubuntu/app.json
{
    "dns": {
      "independent_cache": true,
      "rules": [],
      "servers": [
        {
          "address": "https://8.8.8.8/dns-query",
          "address_resolver": "dns-direct",
          "strategy": "ipv4_only",
          "tag": "dns-remote"
        },
        {
          "address": "local",
          "address_resolver": "dns-local",
          "detour": "direct",
          "strategy": "ipv4_only",
          "tag": "dns-direct"
        },
        {
          "address": "local",
          "detour": "direct",
          "tag": "dns-local"
        },
        {
          "address": "rcode://success",
          "tag": "dns-block"
        }
      ]
    },
    "inbounds": [
      {
        "listen": "127.0.0.1",
        "listen_port": 6450,
        "override_address": "8.8.8.8",
        "override_port": 53,
        "tag": "dns-in",
        "type": "direct"
      },
      {
        "domain_strategy": "",
        "endpoint_independent_nat": true,
        "inet4_address": [
          "172.19.0.1/28"
        ],
        "mtu": 9000,
        "sniff": true,
        "sniff_override_destination": false,
        "stack": "mixed",
        "tag": "tun-in",
        "type": "tun"
      },
      {
        "domain_strategy": "",
        "listen": "127.0.0.1",
        "listen_port": 2080,
        "sniff": true,
        "sniff_override_destination": false,
        "tag": "mixed-in",
        "type": "mixed"
      }
    ],
    "log": {
      "level": "panic"
    },
    "outbounds": [
      {
        "type": "vless",
        "tag": "proxy",
        "server": "13.225.0.89",
        "server_port": 443,
        "uuid": "$UUID1",
        "tls": {
          "enabled": true,
          "disable_sni": true,
          "insecure": true,
          "max_version": "1.2"
        },
        "transport": {
          "type": "ws",
          "path": "/websocket",
          "headers": {
            "Host": "$cfdomain",
            "User-Agent": [
              "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.143 Safari/537.36"
            ]
          },
          "early_data_header_name": "Sec-WebSocket-Protocol"
        },
        "domain_strategy": ""
      },
      {
        "tag": "direct",
        "type": "direct"
      },
      {
        "tag": "bypass",
        "type": "direct"
      },
      {
        "tag": "block",
        "type": "block"
      },
      {
        "tag": "dns-out",
        "type": "dns"
      }
    ],
    "route": {
      "auto_detect_interface": true,
      "rules": [
        {
          "outbound": "dns-out",
          "port": [
            53
          ]
        },
        {
          "inbound": [
            "dns-in"
          ],
          "outbound": "dns-out"
        },
        {
          "ip_cidr": [
            "224.0.0.0/3",
            "ff00::/8"
          ],
          "outbound": "block",
          "source_ip_cidr": [
            "224.0.0.0/3",
            "ff00::/8"
          ]
        }
      ]
    }
  }
EOF

#Config for Singbox

cat << EOF > /home/ubuntu/singbox.json
{
    "log": {
      "disabled": true
    },
    "dns": {
      "servers": [
        {
          "tag": "google",
          "address": "tcp://8.8.4.4",
          "detour": "BFM"
        }
      ],
      "rules": [
        {
          "clash_mode": "direct",
          "server": "local"
        }
      ],
      "strategy": "ipv4_only",
      "final": "google"
    },
    "inbounds": [
      {
        "type": "tun",
        "interface_name": "SingBox",
        "inet4_address": "172.19.0.1/30",
        "inet6_address": "fdfe:dcba:9876::1/126",
        "stack": "mixed",
        "mtu": 1500,
        "auto_route": true,
        "strict_route": true,
        "sniff": true,
        "sniff_override_destination": false
      }
    ],
    "outbounds": [
      {
        "type": "direct",
        "tag": "direct"
      },
      {
        "type": "block",
        "tag": "block"
      },
      {
        "type": "dns",
        "tag": "dns-out"
      },
      {
        "tag": "BFM",
        "type": "selector",
        "outbounds": [
          "D-0",
          "D-0-WARP"
        ]
      },
      { 
        "type": "vless",
        "tag": "D-0",
        "server": "13.225.0.89",
        "server_port": 443,
        "uuid": "$UUID1",
        "tls": {
          "enabled": true,
          "disable_sni": true,
          "insecure": true,
          "max_version": "1.2"
        },
        "transport": {
          "type": "ws",
          "path": "/websocket",
          "headers": {
            "Host": "$cfdomain",
            "User-Agent": [
              "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36"
            ]
          },
          "early_data_header_name": "Sec-WebSocket-Protocol"
        },
        "packet_encoding": "xudp"
      },
      { 
        "type": "vless",
        "tag": "D-0-WARP",
        "server": "13.225.0.89",
        "server_port": 443,
        "uuid": "$UUID3",
        "tls": {
          "enabled": true,
          "disable_sni": true,
          "insecure": true,
          "max_version": "1.2"
        },
        "transport": {
          "type": "ws",
          "path": "/websocket",
          "headers": {
            "Host": "$cfdomain",
            "User-Agent": [
              "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36"
            ]
          },
          "early_data_header_name": "Sec-WebSocket-Protocol"
        },
        "packet_encoding": "xudp"
      }
    ],
  "route": {
    "final": "BFM",
    "rules": [
      {
        "clash_mode": "direct",
        "outbound": "direct"
      },
      {
        "protocol": "dns",
        "outbound": "dns-out"
      },
      {
        "protocol": [
          "quic"
        ],
        "outbound": "block"
      }
    ],
    "auto_detect_interface": true
  },
  "experimental": {
    "clash_api": {
      "external_controller": "localhost:9090",
      "external_ui": "./yacd-gh-pages",
      "store_selected": true
    }
  }
  }
EOF

cp /home/ubuntu/singbox.json /var/www/fallback_site/html/config/singbox.json
cp /home/ubuntu/app.json /var/www/fallback_site/html/config/nekobox.json
#End

echo "The Setup Has been Finished !"
echo "------------------------------"
echo "  project by speed force lk    "
echo "------------------------------"
echo " Your Singbox Config : https://$domain/config/singbox.json "
echo " Your Singbox Config : https://$domain/config/nekobox.json "
echo "------------------------------"
echo "Test Server Status"
sudo systemctl status xray nginx
#done