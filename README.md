# SecureApachePHP
Hal-hal yang dapat dilakukan untuk meningkatkan keamanan pada Apache Server dan PHP pada sisi client
```
ServerSignature Off
ServerTokens Prod
```
Kemudian aktifkan module Header:
```
LoadModule headers_module modules/mod_headers.so
```
Dan tambahkan beberapa setting berikut pada apache2.conf
```
# Security Headers
<IfModule mod_headers.c>
    Header set X-XSS-Protection "1; mode=block"
    Header set X-Frame-Options "SAMEORIGIN"
    Header set X-Content-Type-Options "nosniff"
    Header always set Strict-Transport-Security "max-age=63072000; includeSubDomains"
    # Header set Content-Security-Policy ...
    Header set Referrer-Policy "same-origin"
    Header set Feature-Policy "geolocation 'self'; vibrate 'none'"
</IfModule>
```
Kemudian upayakan untuk menredirect semua koneksi http menjadi https melalui .htaccess (pastikan module rewrite pada apache2 telah diload), dan mengambaikan folderxxxx tertentu:
```
RewriteEngine On
RewriteCond %{HTTPS} off
RewriteRule !^foldexxx($|/) https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301,NE]
```
Kemudian tambahkan beberapa setting berikut pada php.ini
```
expose_php = Off
Session.cookie_secure = 1
session.cookie_httponly = 1
session.cookie_samesite = 1
```
Juga non-aktifkan fungsi-fungsi level system pada php.ini
```
disable_functions =exec,passthru,shell_exec,system,proc_open,popen,curl_exec,curl_multi_exec,parse_ini_file,show_source
```
Menambah lapisan Authentication pada beberapa aplikasi open source tertentu seperti PHPMyAdmin, Webmail, dll
```
AuthType Basic
AuthName "Authentication Required"
AuthUserFile "/etc/apache2/passwd.txt"

# Here is where we allow/deny
Order Deny,Allow
Satisfy any
Deny from all
Require valid-user
Allow from env=noauth
```
Dan buatlah file passwd.txt pada /etc/apache2 dengan isi:
```
tamu:$apr1$h17k5vx4$npEL1R3yLPLcotv3Hkw.v0
```
dimana user adalah tamu, dan password adalah permisi
### Menganti nama alias untuk aplikasi open source seperti phpmyadmin menjadi phpmyadminsecure
```
Alias /phpmyadminsecure /usr/local/phpmyadmin/www
<Directory /usr/local/phpmyadmin/www>
 Options None
```
