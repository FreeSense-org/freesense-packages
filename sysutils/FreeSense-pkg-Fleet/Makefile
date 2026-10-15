PORTNAME=	FreeSense-pkg-Fleet
PORTVERSION=	0.1.0
CATEGORIES=	sysutils
MASTER_SITES=	# empty
DISTFILES=	# empty
EXTRACT_ONLY=	# empty

MAINTAINER=	coreteam@freesense.org
COMMENT=	FreeSense Fleet central management controller
LICENSE=	APACHE20

NO_BUILD=	yes
NO_MTREE=	yes
SUB_FILES=	pkg-install pkg-deinstall
SUB_LIST=	PORTNAME=${PORTNAME}

do-extract:
	${MKDIR} ${WRKSRC}

do-install:
	${MKDIR} ${STAGEDIR}${PREFIX}/pkg/fleet/enroll ${STAGEDIR}${PREFIX}/www/fleet/assets ${STAGEDIR}${PREFIX}/sbin
	${MKDIR} ${STAGEDIR}${PREFIX}/share/${PORTNAME} ${STAGEDIR}/etc/inc/priv
	${INSTALL_DATA} ${FILESDIR}${PREFIX}/pkg/fleet.inc ${STAGEDIR}${PREFIX}/pkg/
	${INSTALL_DATA} ${FILESDIR}${PREFIX}/pkg/fleet.xml ${STAGEDIR}${PREFIX}/pkg/
	${INSTALL_DATA} ${FILESDIR}${PREFIX}/pkg/fleet/*.inc ${STAGEDIR}${PREFIX}/pkg/fleet/
	${INSTALL_DATA} ${FILESDIR}${PREFIX}/pkg/fleet/enroll/index.php ${STAGEDIR}${PREFIX}/pkg/fleet/enroll/
	${INSTALL_SCRIPT} ${FILESDIR}${PREFIX}/sbin/freesense-fleet-backup ${STAGEDIR}${PREFIX}/sbin/
	${INSTALL_SCRIPT} ${FILESDIR}${PREFIX}/sbin/freesense-fleet-poll ${STAGEDIR}${PREFIX}/sbin/
	${INSTALL_DATA} ${FILESDIR}${PREFIX}/www/fleet/*.php ${STAGEDIR}${PREFIX}/www/fleet/
	${INSTALL_DATA} ${FILESDIR}${PREFIX}/www/fleet/assets/* ${STAGEDIR}${PREFIX}/www/fleet/assets/
	${INSTALL_DATA} ${FILESDIR}${PREFIX}/share/${PORTNAME}/info.xml ${STAGEDIR}${PREFIX}/share/${PORTNAME}/
	@${REINPLACE_CMD} -i '' -e "s|%%PKGVERSION%%|${PKGVERSION}|" ${STAGEDIR}${PREFIX}/share/${PORTNAME}/info.xml
	${INSTALL_DATA} ${FILESDIR}/etc/inc/priv/fleet.priv.inc ${STAGEDIR}/etc/inc/priv/

.include <bsd.port.mk>
