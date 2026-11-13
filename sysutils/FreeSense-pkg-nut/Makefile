# $FreeBSD$

PORTNAME=	FreeSense-pkg-nut
PORTVERSION=	2.8.2
PORTREVISION=	14
CATEGORIES=	sysutils
MASTER_SITES=	# empty
DISTFILES=	# empty
EXTRACT_ONLY=	# empty

MAINTAINER=	dev@freesense.org
COMMENT=	Network UPS Tools

LICENSE=	APACHE20

RUN_DEPENDS=	nut>=2.8.2:sysutils/nut

NO_BUILD=	yes
NO_MTREE=	yes

SUB_FILES=	pkg-install pkg-deinstall
SUB_LIST=	PORTNAME=${PORTNAME}

do-extract:
	${MKDIR} ${WRKSRC}

do-install:
	${MKDIR} ${STAGEDIR}${PREFIX}/pkg/nut
	${MKDIR} ${STAGEDIR}/etc/inc/priv
	${MKDIR} ${STAGEDIR}${PREFIX}/www/shortcuts
	${MKDIR} ${STAGEDIR}${DATADIR}
	${MKDIR} ${STAGEDIR}${PREFIX}/www/widgets
	${INSTALL_DATA} ${FILESDIR}${PREFIX}/pkg/nut.xml \
		${STAGEDIR}${PREFIX}/pkg
	${INSTALL_DATA} ${FILESDIR}${PREFIX}/pkg/nut/nut.inc \
		${STAGEDIR}${PREFIX}/pkg/nut
	${INSTALL_DATA} -m 0755 ${FILESDIR}${PREFIX}/pkg/nut/nut_email.php \
		${STAGEDIR}${PREFIX}/pkg/nut
	${INSTALL_DATA} ${FILESDIR}/etc/inc/priv/nut.priv.inc \
		${STAGEDIR}/etc/inc/priv
	${INSTALL_DATA} ${FILESDIR}${PREFIX}/www/shortcuts/pkg_nut.inc \
		${STAGEDIR}${PREFIX}/www/shortcuts
	${INSTALL_DATA} ${FILESDIR}${PREFIX}/www/nut_settings.php \
		${STAGEDIR}${PREFIX}/www
	${INSTALL_DATA} ${FILESDIR}${PREFIX}/www/nut_status.php \
		${STAGEDIR}${PREFIX}/www
	${INSTALL_DATA} ${FILESDIR}${DATADIR}/info.xml \
		${STAGEDIR}${DATADIR}
	${INSTALL_DATA} ${FILESDIR}${PREFIX}/www/widgets/nut.widget.json ${FILESDIR}${PREFIX}/www/widgets/nut.js ${STAGEDIR}${PREFIX}/www/widgets
	@${REINPLACE_CMD} -i '' -e "s|%%PKGVERSION%%|${PKGVERSION}|" \
		${STAGEDIR}${DATADIR}/info.xml

.include <bsd.port.mk>
