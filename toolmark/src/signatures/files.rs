//! The signature files in toolmark/signatures, compiled into the binary.
//!
//! A list of literal paths rather than a folder walked by a build script: the release
//! guard can tell what a binary embeds only from paths it can read, and a walk hides
//! them. `the_compiled_set_is_the_signatures_folder` names any file in the folder that is
//! missing from here.
//!
//! The order is the order detections are reported in, and when two products found
//! imply a third, the first is the one named as implying it.

pub(super) static FILES: &[(&str, &str)] = &[
    ("nginx.yaml", include_str!("../../signatures/nginx.yaml")),
    (
        "apache-httpd.yaml",
        include_str!("../../signatures/apache-httpd.yaml"),
    ),
    ("iis.yaml", include_str!("../../signatures/iis.yaml")),
    (
        "openresty.yaml",
        include_str!("../../signatures/openresty.yaml"),
    ),
    (
        "litespeed.yaml",
        include_str!("../../signatures/litespeed.yaml"),
    ),
    ("tomcat.yaml", include_str!("../../signatures/tomcat.yaml")),
    ("jetty.yaml", include_str!("../../signatures/jetty.yaml")),
    (
        "gunicorn.yaml",
        include_str!("../../signatures/gunicorn.yaml"),
    ),
    (
        "kestrel.yaml",
        include_str!("../../signatures/kestrel.yaml"),
    ),
    (
        "werkzeug.yaml",
        include_str!("../../signatures/werkzeug.yaml"),
    ),
    ("php.yaml", include_str!("../../signatures/php.yaml")),
    ("aspnet.yaml", include_str!("../../signatures/aspnet.yaml")),
    (
        "aspnet-core.yaml",
        include_str!("../../signatures/aspnet-core.yaml"),
    ),
    (
        "express.yaml",
        include_str!("../../signatures/express.yaml"),
    ),
    (
        "laravel.yaml",
        include_str!("../../signatures/laravel.yaml"),
    ),
    ("django.yaml", include_str!("../../signatures/django.yaml")),
    ("flask.yaml", include_str!("../../signatures/flask.yaml")),
    ("rails.yaml", include_str!("../../signatures/rails.yaml")),
    ("spring.yaml", include_str!("../../signatures/spring.yaml")),
    (
        "wordpress.yaml",
        include_str!("../../signatures/wordpress.yaml"),
    ),
    ("drupal.yaml", include_str!("../../signatures/drupal.yaml")),
    ("joomla.yaml", include_str!("../../signatures/joomla.yaml")),
    (
        "magento.yaml",
        include_str!("../../signatures/magento.yaml"),
    ),
    ("ghost.yaml", include_str!("../../signatures/ghost.yaml")),
    ("nextjs.yaml", include_str!("../../signatures/nextjs.yaml")),
    ("nuxtjs.yaml", include_str!("../../signatures/nuxtjs.yaml")),
    ("react.yaml", include_str!("../../signatures/react.yaml")),
    ("vuejs.yaml", include_str!("../../signatures/vuejs.yaml")),
    (
        "angular.yaml",
        include_str!("../../signatures/angular.yaml"),
    ),
    ("jquery.yaml", include_str!("../../signatures/jquery.yaml")),
    (
        "bootstrap.yaml",
        include_str!("../../signatures/bootstrap.yaml"),
    ),
    (
        "cloudflare.yaml",
        include_str!("../../signatures/cloudflare.yaml"),
    ),
    (
        "varnish.yaml",
        include_str!("../../signatures/varnish.yaml"),
    ),
    (
        "shopify.yaml",
        include_str!("../../signatures/shopify.yaml"),
    ),
    ("wix.yaml", include_str!("../../signatures/wix.yaml")),
    (
        "squarespace.yaml",
        include_str!("../../signatures/squarespace.yaml"),
    ),
    (
        "spring-boot.yaml",
        include_str!("../../signatures/spring-boot.yaml"),
    ),
    (
        "symfony.yaml",
        include_str!("../../signatures/symfony.yaml"),
    ),
    (
        "jenkins.yaml",
        include_str!("../../signatures/jenkins.yaml"),
    ),
    ("gitlab.yaml", include_str!("../../signatures/gitlab.yaml")),
    (
        "sonarqube.yaml",
        include_str!("../../signatures/sonarqube.yaml"),
    ),
    ("harbor.yaml", include_str!("../../signatures/harbor.yaml")),
    (
        "grafana.yaml",
        include_str!("../../signatures/grafana.yaml"),
    ),
    ("kibana.yaml", include_str!("../../signatures/kibana.yaml")),
    ("zabbix.yaml", include_str!("../../signatures/zabbix.yaml")),
    ("sentry.yaml", include_str!("../../signatures/sentry.yaml")),
    (
        "phpmyadmin.yaml",
        include_str!("../../signatures/phpmyadmin.yaml"),
    ),
    ("consul.yaml", include_str!("../../signatures/consul.yaml")),
    ("vault.yaml", include_str!("../../signatures/vault.yaml")),
    ("minio.yaml", include_str!("../../signatures/minio.yaml")),
    (
        "confluence.yaml",
        include_str!("../../signatures/confluence.yaml"),
    ),
    (
        "confluence-server.yaml",
        include_str!("../../signatures/confluence-server.yaml"),
    ),
    (
        "confluence-data-center.yaml",
        include_str!("../../signatures/confluence-data-center.yaml"),
    ),
    ("jira.yaml", include_str!("../../signatures/jira.yaml")),
    (
        "exchange.yaml",
        include_str!("../../signatures/exchange.yaml"),
    ),
    (
        "sharepoint.yaml",
        include_str!("../../signatures/sharepoint.yaml"),
    ),
    (
        "citrix-netscaler.yaml",
        include_str!("../../signatures/citrix-netscaler.yaml"),
    ),
    (
        "f5-big-ip.yaml",
        include_str!("../../signatures/f5-big-ip.yaml"),
    ),
    (
        "fortinet.yaml",
        include_str!("../../signatures/fortinet.yaml"),
    ),
    (
        "fortios.yaml",
        include_str!("../../signatures/fortios.yaml"),
    ),
    (
        "fortiproxy.yaml",
        include_str!("../../signatures/fortiproxy.yaml"),
    ),
    (
        "ivanti-gateway.yaml",
        include_str!("../../signatures/ivanti-gateway.yaml"),
    ),
    (
        "ivanti-connect-secure.yaml",
        include_str!("../../signatures/ivanti-connect-secure.yaml"),
    ),
    (
        "ivanti-policy-secure.yaml",
        include_str!("../../signatures/ivanti-policy-secure.yaml"),
    ),
    (
        "weblogic.yaml",
        include_str!("../../signatures/weblogic.yaml"),
    ),
    ("zimbra.yaml", include_str!("../../signatures/zimbra.yaml")),
    (
        "roundcube.yaml",
        include_str!("../../signatures/roundcube.yaml"),
    ),
    (
        "moveit-transfer.yaml",
        include_str!("../../signatures/moveit-transfer.yaml"),
    ),
    (
        "globalprotect.yaml",
        include_str!("../../signatures/globalprotect.yaml"),
    ),
    (
        "cisco-webvpn.yaml",
        include_str!("../../signatures/cisco-webvpn.yaml"),
    ),
    (
        "cisco-asa.yaml",
        include_str!("../../signatures/cisco-asa.yaml"),
    ),
    (
        "cisco-ftd.yaml",
        include_str!("../../signatures/cisco-ftd.yaml"),
    ),
    (
        "vmware-vcenter.yaml",
        include_str!("../../signatures/vmware-vcenter.yaml"),
    ),
    (
        "vmware-esxi.yaml",
        include_str!("../../signatures/vmware-esxi.yaml"),
    ),
    (
        "screenconnect.yaml",
        include_str!("../../signatures/screenconnect.yaml"),
    ),
    (
        "crushftp.yaml",
        include_str!("../../signatures/crushftp.yaml"),
    ),
    (
        "miniserv.yaml",
        include_str!("../../signatures/miniserv.yaml"),
    ),
    ("webmin.yaml", include_str!("../../signatures/webmin.yaml")),
    (
        "usermin.yaml",
        include_str!("../../signatures/usermin.yaml"),
    ),
    (
        "telerik-ui-aspnet-ajax.yaml",
        include_str!("../../signatures/telerik-ui-aspnet-ajax.yaml"),
    ),
    (
        "craft-cms.yaml",
        include_str!("../../signatures/craft-cms.yaml"),
    ),
    (
        "elasticsearch.yaml",
        include_str!("../../signatures/elasticsearch.yaml"),
    ),
    (
        "apache-ofbiz.yaml",
        include_str!("../../signatures/apache-ofbiz.yaml"),
    ),
    (
        "apache-solr.yaml",
        include_str!("../../signatures/apache-solr.yaml"),
    ),
    (
        "liferay.yaml",
        include_str!("../../signatures/liferay.yaml"),
    ),
    (
        "liferay-portal.yaml",
        include_str!("../../signatures/liferay-portal.yaml"),
    ),
    (
        "apache-activemq.yaml",
        include_str!("../../signatures/apache-activemq.yaml"),
    ),
    (
        "oracle-ebs.yaml",
        include_str!("../../signatures/oracle-ebs.yaml"),
    ),
    (
        "sap-netweaver.yaml",
        include_str!("../../signatures/sap-netweaver.yaml"),
    ),
    (
        "juniper-jweb.yaml",
        include_str!("../../signatures/juniper-jweb.yaml"),
    ),
    ("cacti.yaml", include_str!("../../signatures/cacti.yaml")),
    (
        "openfire.yaml",
        include_str!("../../signatures/openfire.yaml"),
    ),
    (
        "openssh.yaml",
        include_str!("../../signatures/openssh.yaml"),
    ),
    (
        "openssh-windows.yaml",
        include_str!("../../signatures/openssh-windows.yaml"),
    ),
    (
        "dropbear.yaml",
        include_str!("../../signatures/dropbear.yaml"),
    ),
    (
        "erlang-otp-ssh.yaml",
        include_str!("../../signatures/erlang-otp-ssh.yaml"),
    ),
    ("libssh.yaml", include_str!("../../signatures/libssh.yaml")),
    ("vsftpd.yaml", include_str!("../../signatures/vsftpd.yaml")),
    (
        "proftpd.yaml",
        include_str!("../../signatures/proftpd.yaml"),
    ),
    (
        "pure-ftpd.yaml",
        include_str!("../../signatures/pure-ftpd.yaml"),
    ),
    (
        "filezilla-server.yaml",
        include_str!("../../signatures/filezilla-server.yaml"),
    ),
    (
        "postfix.yaml",
        include_str!("../../signatures/postfix.yaml"),
    ),
    ("exim.yaml", include_str!("../../signatures/exim.yaml")),
    (
        "sendmail.yaml",
        include_str!("../../signatures/sendmail.yaml"),
    ),
    (
        "opensmtpd.yaml",
        include_str!("../../signatures/opensmtpd.yaml"),
    ),
    (
        "mariadb.yaml",
        include_str!("../../signatures/mariadb.yaml"),
    ),
    (
        "ingress-nginx.yaml",
        include_str!("../../signatures/ingress-nginx.yaml"),
    ),
    (
        "traefik.yaml",
        include_str!("../../signatures/traefik.yaml"),
    ),
    (
        "nostromo.yaml",
        include_str!("../../signatures/nostromo.yaml"),
    ),
    (
        "rejetto-hfs.yaml",
        include_str!("../../signatures/rejetto-hfs.yaml"),
    ),
    ("jboss.yaml", include_str!("../../signatures/jboss.yaml")),
    (
        "goanywhere-mft.yaml",
        include_str!("../../signatures/goanywhere-mft.yaml"),
    ),
    (
        "manageengine-servicedesk-plus.yaml",
        include_str!("../../signatures/manageengine-servicedesk-plus.yaml"),
    ),
    (
        "manageengine-adselfservice-plus.yaml",
        include_str!("../../signatures/manageengine-adselfservice-plus.yaml"),
    ),
    ("caddy.yaml", include_str!("../../signatures/caddy.yaml")),
    ("envoy.yaml", include_str!("../../signatures/envoy.yaml")),
    (
        "tengine.yaml",
        include_str!("../../signatures/tengine.yaml"),
    ),
    (
        "webflow.yaml",
        include_str!("../../signatures/webflow.yaml"),
    ),
    ("typo3.yaml", include_str!("../../signatures/typo3.yaml")),
    (
        "prestashop.yaml",
        include_str!("../../signatures/prestashop.yaml"),
    ),
    ("bitrix.yaml", include_str!("../../signatures/bitrix.yaml")),
    ("tilda.yaml", include_str!("../../signatures/tilda.yaml")),
    (
        "adobe-experience-manager.yaml",
        include_str!("../../signatures/adobe-experience-manager.yaml"),
    ),
    (
        "blogger.yaml",
        include_str!("../../signatures/blogger.yaml"),
    ),
    ("lodash.yaml", include_str!("../../signatures/lodash.yaml")),
    ("moment.yaml", include_str!("../../signatures/moment.yaml")),
    (
        "underscore.yaml",
        include_str!("../../signatures/underscore.yaml"),
    ),
    (
        "handlebars.yaml",
        include_str!("../../signatures/handlebars.yaml"),
    ),
    (
        "backbone.yaml",
        include_str!("../../signatures/backbone.yaml"),
    ),
    ("popper.yaml", include_str!("../../signatures/popper.yaml")),
    (
        "modernizr.yaml",
        include_str!("../../signatures/modernizr.yaml"),
    ),
    ("gsap.yaml", include_str!("../../signatures/gsap.yaml")),
    ("swiper.yaml", include_str!("../../signatures/swiper.yaml")),
    (
        "alpinejs.yaml",
        include_str!("../../signatures/alpinejs.yaml"),
    ),
    (
        "chartjs.yaml",
        include_str!("../../signatures/chartjs.yaml"),
    ),
    ("d3.yaml", include_str!("../../signatures/d3.yaml")),
    (
        "apache-traffic-server.yaml",
        include_str!("../../signatures/apache-traffic-server.yaml"),
    ),
    (
        "uvicorn.yaml",
        include_str!("../../signatures/uvicorn.yaml"),
    ),
    (
        "tornado.yaml",
        include_str!("../../signatures/tornado.yaml"),
    ),
    ("cowboy.yaml", include_str!("../../signatures/cowboy.yaml")),
    ("squid.yaml", include_str!("../../signatures/squid.yaml")),
    (
        "lighttpd.yaml",
        include_str!("../../signatures/lighttpd.yaml"),
    ),
    (
        "http-sys.yaml",
        include_str!("../../signatures/http-sys.yaml"),
    ),
    (
        "webrick.yaml",
        include_str!("../../signatures/webrick.yaml"),
    ),
    ("thttpd.yaml", include_str!("../../signatures/thttpd.yaml")),
    ("boa.yaml", include_str!("../../signatures/boa.yaml")),
    (
        "goahead.yaml",
        include_str!("../../signatures/goahead.yaml"),
    ),
    (
        "mini-httpd.yaml",
        include_str!("../../signatures/mini-httpd.yaml"),
    ),
    ("resin.yaml", include_str!("../../signatures/resin.yaml")),
    (
        "ibm-http-server.yaml",
        include_str!("../../signatures/ibm-http-server.yaml"),
    ),
    (
        "woocommerce.yaml",
        include_str!("../../signatures/woocommerce.yaml"),
    ),
    (
        "elementor.yaml",
        include_str!("../../signatures/elementor.yaml"),
    ),
    (
        "contact-form-7.yaml",
        include_str!("../../signatures/contact-form-7.yaml"),
    ),
    (
        "jetpack.yaml",
        include_str!("../../signatures/jetpack.yaml"),
    ),
    (
        "yoast-seo.yaml",
        include_str!("../../signatures/yoast-seo.yaml"),
    ),
    ("java.yaml", include_str!("../../signatures/java.yaml")),
    ("python.yaml", include_str!("../../signatures/python.yaml")),
    ("nodejs.yaml", include_str!("../../signatures/nodejs.yaml")),
    ("ruby.yaml", include_str!("../../signatures/ruby.yaml")),
    ("mysql.yaml", include_str!("../../signatures/mysql.yaml")),
];
