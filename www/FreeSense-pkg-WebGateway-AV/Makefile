PORTNAME=	FreeSense-pkg-WebGateway-AV
PORTVERSION=	2.0.1
CATEGORIES=	www security
MASTER_SITES=	# empty
DISTFILES=	# empty

MAINTAINER=	dev@freesense.org
COMMENT=	Local malware scanning companion for FreeSense Web Gateway
WWW=		https://freesense.org/

LICENSE=	APACHE20

RUN_DEPENDS=	FreeSense-pkg-WebGateway>=2:www/FreeSense-pkg-WebGateway \
		clamav>=0:security/clamav \
		c-icap>=0:www/c-icap \
		c-icap-modules>=0:www/c-icap-modules \
		squidclamav>=0:www/squidclamav

NO_BUILD=	yes
NO_MTREE=	yes

SUB_FILES=	pkg-install pkg-deinstall
SUB_LIST=	PORTNAME=${PORTNAME}

do-extract:
	${MKDIR} ${WRKSRC}

do-install:
	${MKDIR} ${STAGEDIR}${PREFIX}/pkg
	${MKDIR} ${STAGEDIR}${DATADIR}
	${INSTALL_DATA} ${FILESDIR}${PREFIX}/pkg/webgateway_av.xml ${STAGEDIR}${PREFIX}/pkg
	${INSTALL_DATA} ${FILESDIR}${DATADIR}/info.xml ${STAGEDIR}${DATADIR}
	@${REINPLACE_CMD} -i '' -e "s|%%PKGVERSION%%|${PKGVERSION}|" ${STAGEDIR}${DATADIR}/info.xml

.include <bsd.port.mk>
