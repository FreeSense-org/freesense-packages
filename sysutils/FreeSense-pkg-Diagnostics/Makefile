PORTNAME=	FreeSense-pkg-Diagnostics
PORTVERSION=	1.0.0
CATEGORIES=	sysutils
MASTER_SITES=	# empty
DISTFILES=	# empty
EXTRACT_ONLY=	# empty

MAINTAINER=	dev@freesense.org
COMMENT=	FreeSense network diagnostics suite
LICENSE=	APACHE20

RUN_DEPENDS=	arping:net/arping \
		iperf3:benchmarks/iperf3 \
		mtr:net/mtr@nox11 \
		nmap:security/nmap

NO_BUILD=	yes
NO_MTREE=	yes
SUB_FILES=	pkg-install pkg-deinstall
SUB_LIST=	PORTNAME=${PORTNAME}

do-extract:
	${MKDIR} ${WRKSRC}

do-install:
	${MKDIR} ${STAGEDIR}${PREFIX}/www/diagnostics
	${MKDIR} ${STAGEDIR}${PREFIX}/pkg
	${MKDIR} ${STAGEDIR}${PREFIX}/share/${PORTNAME}
	${MKDIR} ${STAGEDIR}/etc/inc/priv
	${INSTALL_DATA} ${FILESDIR}${PREFIX}/www/diagnostics/network_tools.php \
		${STAGEDIR}${PREFIX}/www/diagnostics/
	${INSTALL_DATA} ${FILESDIR}${PREFIX}/pkg/diagnostics.xml ${STAGEDIR}${PREFIX}/pkg/
	${INSTALL_DATA} ${FILESDIR}${PREFIX}/share/${PORTNAME}/info.xml \
		${STAGEDIR}${PREFIX}/share/${PORTNAME}/
	${INSTALL_DATA} ${FILESDIR}/etc/inc/priv/diagnostics.priv.inc \
		${STAGEDIR}/etc/inc/priv/

.include <bsd.port.mk>
