PORTNAME=	FreeSense-pkg-ThreatShield
PORTVERSION=	1.0.0
CATEGORIES=	security
MASTER_SITES=	# empty
DISTFILES=	# empty
EXTRACT_ONLY=	# empty

MAINTAINER=	coreteam@freesense.org
COMMENT=	FreeSense Threat Shield & DNS Protection integration
LICENSE=	APACHE20

RUN_DEPENDS=	${LOCALBASE}/bin/AdGuardHome:www/adguardhome-bin

NO_BUILD=	yes
NO_MTREE=	yes
SUB_FILES=	pkg-install pkg-deinstall
SUB_LIST=	PORTNAME=${PORTNAME}

do-extract:
	${MKDIR} ${WRKSRC}

do-install:
	${MKDIR} ${STAGEDIR}${PREFIX}/pkg/threatshield ${STAGEDIR}${PREFIX}/www/threatshield
	${MKDIR} ${STAGEDIR}${PREFIX}/www/widgets/widgets ${STAGEDIR}${PREFIX}/www/shortcuts
	${MKDIR} ${STAGEDIR}${PREFIX}/share/${PORTNAME} ${STAGEDIR}/etc/inc/priv
	${MKDIR} ${STAGEDIR}${PREFIX}/etc/rc.d ${STAGEDIR}${PREFIX}/sbin
	${INSTALL_DATA} ${FILESDIR}${PREFIX}/pkg/threatshield.inc ${STAGEDIR}${PREFIX}/pkg/
	${INSTALL_DATA} ${FILESDIR}${PREFIX}/pkg/threatshield.xml ${STAGEDIR}${PREFIX}/pkg/
	${INSTALL_SCRIPT} ${FILESDIR}${PREFIX}/pkg/threatshield_sync.php ${STAGEDIR}${PREFIX}/pkg/
	${INSTALL_SCRIPT} ${FILESDIR}${PREFIX}/pkg/threatshield_update.php ${STAGEDIR}${PREFIX}/pkg/
	${INSTALL_SCRIPT} ${FILESDIR}${PREFIX}/sbin/freesense-threatshield-update ${STAGEDIR}${PREFIX}/sbin/
	${INSTALL_SCRIPT} ${FILESDIR}${PREFIX}/etc/rc.d/threatshield ${STAGEDIR}${PREFIX}/etc/rc.d/
	${INSTALL_DATA} ${FILESDIR}${PREFIX}/www/threatshield/*.php ${STAGEDIR}${PREFIX}/www/threatshield/
	${INSTALL_DATA} ${FILESDIR}${PREFIX}/www/shortcuts/pkg_threatshield.inc ${STAGEDIR}${PREFIX}/www/shortcuts/
	${INSTALL_DATA} ${FILESDIR}${PREFIX}/www/widgets/widgets/threatshield.widget.php ${STAGEDIR}${PREFIX}/www/widgets/widgets/
	${INSTALL_DATA} ${FILESDIR}${PREFIX}/share/${PORTNAME}/info.xml ${STAGEDIR}${PREFIX}/share/${PORTNAME}/
	${INSTALL_DATA} ${FILESDIR}/etc/inc/priv/threatshield.priv.inc ${STAGEDIR}/etc/inc/priv/

.include <bsd.port.mk>
