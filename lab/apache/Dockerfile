ARG PHP_VERSION
FROM php:${PHP_VERSION}-apache

# Production ini (display_errors=Off, log_errors=On).
# mod_logio (%I/%O) is built in statically on Debian Apache, no a2enmod needed.
RUN cp "$PHP_INI_DIR/php.ini-production" "$PHP_INI_DIR/php.ini"

COPY php/lab.ini $PHP_INI_DIR/conf.d/zz-lab.ini
COPY apache/lab.conf /etc/apache2/conf-enabled/zz-lab.conf
