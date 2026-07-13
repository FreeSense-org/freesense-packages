PORTNAME=	openvpn-client-export
PORTVERSION=	2.6.17
CATEGORIES=	security
MASTER_SITES=	https://github.com/FreeSense-org/freesense-packages/releases/download/distfile-${PORTNAME}-${PORTVERSION}/ \
		https://pkg.freesense.org/ports-cache/main/distfiles/
EXTRACT_SUFX=	.tgz

MAINTAINER=	dev@freesense.org
COMMENT=	OpenVPN Client Export
WWW=		https://docs.freesense.org/packages/

LICENSE=	APACHE20

RUN_DEPENDS=	openvpn>=2.6.0:security/openvpn

WRKSRC=		${WRKDIR}/client-export

NO_BUILD=	yes
NO_MTREE=	yes

do-install:
	${MKDIR} ${STAGEDIR}${PREFIX}/share/openvpn/client-export
	${CP} -r ${WRKSRC}/* ${STAGEDIR}${PREFIX}/share/openvpn/client-export

.include <bsd.port.mk>
