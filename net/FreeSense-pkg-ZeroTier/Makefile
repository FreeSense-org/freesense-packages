PORTNAME=	FreeSense-pkg-ZeroTier
PORTVERSION=	1.0.0
CATEGORIES=	net
MASTER_SITES=	# empty
DISTFILES=	# empty
EXTRACT_ONLY=	# empty

MAINTAINER=	dev@freesense.org
COMMENT=	FreeSense ZeroTier network integration
LICENSE=	APACHE20

RUN_DEPENDS=	zerotier>=1.16.0:net/zerotier

NO_BUILD=	yes
NO_MTREE=	yes
SUB_FILES=	pkg-install pkg-deinstall
SUB_LIST=	PORTNAME=${PORTNAME}

do-extract:
	${MKDIR} ${WRKSRC}

do-install:
	${MKDIR} ${STAGEDIR}${PREFIX}/pkg/zerotier ${STAGEDIR}${PREFIX}/www/zerotier
	${MKDIR} ${STAGEDIR}${PREFIX}/share/${PORTNAME} ${STAGEDIR}/etc/inc/priv
	${INSTALL_DATA} ${FILESDIR}${PREFIX}/pkg/zerotier/zerotier.inc ${STAGEDIR}${PREFIX}/pkg/zerotier/
	${INSTALL_DATA} ${FILESDIR}${PREFIX}/pkg/zerotier.xml ${STAGEDIR}${PREFIX}/pkg/
	${INSTALL_DATA} ${FILESDIR}${PREFIX}/www/zerotier/zerotier.php ${STAGEDIR}${PREFIX}/www/zerotier/
	${INSTALL_DATA} ${FILESDIR}${PREFIX}/www/zerotier/zerotier_peers.php ${STAGEDIR}${PREFIX}/www/zerotier/
	${INSTALL_DATA} ${FILESDIR}${PREFIX}/share/${PORTNAME}/info.xml ${STAGEDIR}${PREFIX}/share/${PORTNAME}/
	${INSTALL_DATA} ${FILESDIR}/etc/inc/priv/zerotier.priv.inc ${STAGEDIR}/etc/inc/priv/

.include <bsd.port.mk>
