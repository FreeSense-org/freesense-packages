PORTNAME=	FreeSense-pkg-CrowdSec
PORTVERSION=	1.0.0
CATEGORIES=	security
MASTER_SITES=	# empty
DISTFILES=	# empty
EXTRACT_ONLY=	# empty

MAINTAINER=	dev@freesense.org
COMMENT=	FreeSense CrowdSec threat-response integration
LICENSE=	APACHE20

RUN_DEPENDS=	crowdsec>=1.7.8:security/crowdsec

NO_BUILD=	yes
NO_MTREE=	yes
SUB_FILES=	pkg-install pkg-deinstall
SUB_LIST=	PORTNAME=${PORTNAME}

do-extract:
	${MKDIR} ${WRKSRC}

do-install:
	${MKDIR} ${STAGEDIR}${PREFIX}/pkg/crowdsec ${STAGEDIR}${PREFIX}/www/crowdsec
	${MKDIR} ${STAGEDIR}${PREFIX}/share/${PORTNAME} ${STAGEDIR}/etc/inc/priv
	${INSTALL_DATA} ${FILESDIR}${PREFIX}/pkg/crowdsec/crowdsec.inc ${STAGEDIR}${PREFIX}/pkg/crowdsec/
	${INSTALL_SCRIPT} ${FILESDIR}${PREFIX}/pkg/crowdsec/crowdsec_sync.php ${STAGEDIR}${PREFIX}/pkg/crowdsec/
	${INSTALL_DATA} ${FILESDIR}${PREFIX}/pkg/crowdsec.xml ${STAGEDIR}${PREFIX}/pkg/
	${INSTALL_DATA} ${FILESDIR}${PREFIX}/www/crowdsec/crowdsec.php ${STAGEDIR}${PREFIX}/www/crowdsec/
	${INSTALL_DATA} ${FILESDIR}${PREFIX}/www/crowdsec/crowdsec_decisions.php ${STAGEDIR}${PREFIX}/www/crowdsec/
	${INSTALL_DATA} ${FILESDIR}${PREFIX}/share/${PORTNAME}/info.xml ${STAGEDIR}${PREFIX}/share/${PORTNAME}/
	${INSTALL_DATA} ${FILESDIR}/etc/inc/priv/crowdsec.priv.inc ${STAGEDIR}/etc/inc/priv/

.include <bsd.port.mk>
