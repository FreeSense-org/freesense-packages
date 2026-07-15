PORTNAME=	FreeSense-pkg-WebGateway
PORTVERSION=	2.0.4
CATEGORIES=	www
MASTER_SITES=	# empty
DISTFILES=	# empty

MAINTAINER=	dev@freesense.org
COMMENT=	FreeSense Secure Web Gateway
WWW=		https://freesense.org/

LICENSE=	APACHE20

RUN_DEPENDS=	squid>=7:www/squid

NO_BUILD=	yes
NO_MTREE=	yes

SUB_FILES=	pkg-install pkg-deinstall
SUB_LIST=	PORTNAME=${PORTNAME}

do-extract:
	${MKDIR} ${WRKSRC}

do-install:
	${MKDIR} ${STAGEDIR}${PREFIX}/pkg
	${MKDIR} ${STAGEDIR}${PREFIX}/www/webgateway
	${MKDIR} ${STAGEDIR}${PREFIX}/www/shortcuts
	${MKDIR} ${STAGEDIR}${PREFIX}/etc/rc.d
	${MKDIR} ${STAGEDIR}${PREFIX}/sbin
	${MKDIR} ${STAGEDIR}/etc/inc/priv
	${MKDIR} ${STAGEDIR}${DATADIR}
	${INSTALL_DATA} ${FILESDIR}${PREFIX}/pkg/webgateway.xml \
		${STAGEDIR}${PREFIX}/pkg
	${INSTALL_DATA} ${FILESDIR}${PREFIX}/pkg/webgateway.inc \
		${STAGEDIR}${PREFIX}/pkg
	${INSTALL_SCRIPT} ${FILESDIR}${PREFIX}/etc/rc.d/freesense_webgateway \
		${STAGEDIR}${PREFIX}/etc/rc.d
	${INSTALL_SCRIPT} ${FILESDIR}${PREFIX}/etc/rc.d/freesense_webgateway_watchdog \
		${STAGEDIR}${PREFIX}/etc/rc.d
	${INSTALL_SCRIPT} ${FILESDIR}${PREFIX}/sbin/freesense-webgateway-feed-update \
		${STAGEDIR}${PREFIX}/sbin
	${INSTALL_SCRIPT} ${FILESDIR}${PREFIX}/sbin/freesense-webgateway-watchdog \
		${STAGEDIR}${PREFIX}/sbin
	${INSTALL_DATA} ${FILESDIR}/etc/inc/priv/webgateway.priv.inc \
		${STAGEDIR}/etc/inc/priv
	${INSTALL_DATA} ${FILESDIR}${PREFIX}/www/webgateway/webgateway.php \
		${STAGEDIR}${PREFIX}/www/webgateway
	${INSTALL_DATA} ${FILESDIR}${PREFIX}/www/webgateway/webgateway_listeners.php \
		${STAGEDIR}${PREFIX}/www/webgateway
	${INSTALL_DATA} ${FILESDIR}${PREFIX}/www/webgateway/webgateway_tls.php \
		${STAGEDIR}${PREFIX}/www/webgateway
	${INSTALL_DATA} ${FILESDIR}${PREFIX}/www/webgateway/webgateway_policies.php \
		${STAGEDIR}${PREFIX}/www/webgateway
	${INSTALL_DATA} ${FILESDIR}${PREFIX}/www/webgateway/webgateway_identity.php \
		${STAGEDIR}${PREFIX}/www/webgateway
	${INSTALL_DATA} ${FILESDIR}${PREFIX}/www/webgateway/webgateway_threat.php \
		${STAGEDIR}${PREFIX}/www/webgateway
	${INSTALL_DATA} ${FILESDIR}${PREFIX}/www/webgateway/webgateway_feeds.php \
		${STAGEDIR}${PREFIX}/www/webgateway
	${INSTALL_DATA} ${FILESDIR}${PREFIX}/www/webgateway/webgateway_cache.php \
		${STAGEDIR}${PREFIX}/www/webgateway
	${INSTALL_DATA} ${FILESDIR}${PREFIX}/www/webgateway/webgateway_status.php \
		${STAGEDIR}${PREFIX}/www/webgateway
	${INSTALL_DATA} ${FILESDIR}${PREFIX}/www/webgateway/webgateway_diagnostics.php \
		${STAGEDIR}${PREFIX}/www/webgateway
	${INSTALL_DATA} ${FILESDIR}${PREFIX}/www/webgateway/webgateway_pac.php \
		${STAGEDIR}${PREFIX}/www/webgateway
	${INSTALL_DATA} ${FILESDIR}${PREFIX}/www/shortcuts/pkg_webgateway.inc \
		${STAGEDIR}${PREFIX}/www/shortcuts
	${INSTALL_DATA} ${FILESDIR}${DATADIR}/info.xml \
		${STAGEDIR}${DATADIR}
	@${REINPLACE_CMD} -i '' -e "s|%%PKGVERSION%%|${PKGVERSION}|" \
		${STAGEDIR}${DATADIR}/info.xml

.include <bsd.port.mk>
