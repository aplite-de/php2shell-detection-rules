ARG PHP_VERSION
FROM php:${PHP_VERSION}-fpm

RUN cp "$PHP_INI_DIR/php.ini-production" "$PHP_INI_DIR/php.ini" \
 && mkdir -p /var/log/php-fpm

COPY php/lab.ini $PHP_INI_DIR/conf.d/zz-lab.ini
COPY fpm/zz-lab.conf /usr/local/etc/php-fpm.d/zz-lab.conf
