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
    ("java.yaml", include_str!("../../signatures/java.yaml")),
    ("python.yaml", include_str!("../../signatures/python.yaml")),
    ("nodejs.yaml", include_str!("../../signatures/nodejs.yaml")),
    ("ruby.yaml", include_str!("../../signatures/ruby.yaml")),
    ("mysql.yaml", include_str!("../../signatures/mysql.yaml")),
];
