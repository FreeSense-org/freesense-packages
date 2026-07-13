PORTNAME=	FreeSense-pkg-Automation
PORTVERSION=	1.0.0
CATEGORIES=	sysutils
MASTER_SITES=	# empty
DISTFILES=	# empty
EXTRACT_ONLY=	# empty

MAINTAINER=	dev@freesense.org
COMMENT=	FreeSense scheduled tasks and service watchdog
LICENSE=	APACHE20

NO_BUILD=	yes
NO_MTREE=	yes
SUB_FILES=	pkg-install pkg-deinstall
SUB_LIST=	PORTNAME=${PORTNAME}

do-extract:
	${MKDIR} ${WRKSRC}

do-install:
	${MKDIR} ${STAGEDIR}${PREFIX}/pkg/automation
	${MKDIR} ${STAGEDIR}${PREFIX}/www/automation
	${MKDIR} ${STAGEDIR}${PREFIX}/share/${PORTNAME}
	${MKDIR} ${STAGEDIR}/etc/inc/priv
	${INSTALL_DATA} ${FILESDIR}${PREFIX}/pkg/automation/automation.inc ${STAGEDIR}${PREFIX}/pkg/automation/
	${INSTALL_SCRIPT} ${FILESDIR}${PREFIX}/pkg/automation/automation_watchdog.php ${STAGEDIR}${PREFIX}/pkg/automation/
	${INSTALL_DATA} ${FILESDIR}${PREFIX}/pkg/automation.xml ${STAGEDIR}${PREFIX}/pkg/
	${INSTALL_DATA} ${FILESDIR}${PREFIX}/www/automation/automation.php ${STAGEDIR}${PREFIX}/www/automation/
	${INSTALL_DATA} ${FILESDIR}${PREFIX}/share/${PORTNAME}/info.xml ${STAGEDIR}${PREFIX}/share/${PORTNAME}/
	${INSTALL_DATA} ${FILESDIR}/etc/inc/priv/automation.priv.inc ${STAGEDIR}/etc/inc/priv/

.include <bsd.port.mk>
