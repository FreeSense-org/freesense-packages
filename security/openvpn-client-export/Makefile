PORTNAME=	openvpn-client-export
PORTVERSION=	2.6.17
PORTREVISION=	1
CATEGORIES=	security

MAINTAINER=	dev@freesense.org
COMMENT=	FreeSense OpenVPN client export assets
WWW=		https://docs.freesense.org/packages/

LICENSE=	APACHE20

RUN_DEPENDS=	openvpn>=2.6.0:security/openvpn

NO_BUILD=	yes
NO_MTREE=	yes
NO_ARCH=	yes

do-install:
	${MKDIR} ${STAGEDIR}${PREFIX}/share/openvpn/client-export
	(cd ${FILESDIR}/client-export && \
		${COPYTREE_SHARE} . ${STAGEDIR}${PREFIX}/share/openvpn/client-export)

.include <bsd.port.mk>
