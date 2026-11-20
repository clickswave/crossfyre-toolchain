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
    ("java.yaml", include_str!("../../signatures/java.yaml")),
    ("python.yaml", include_str!("../../signatures/python.yaml")),
    ("nodejs.yaml", include_str!("../../signatures/nodejs.yaml")),
    ("ruby.yaml", include_str!("../../signatures/ruby.yaml")),
    ("mysql.yaml", include_str!("../../signatures/mysql.yaml")),
];
