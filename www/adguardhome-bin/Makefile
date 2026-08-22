PORTNAME=	adguardhome-bin
PORTVERSION=	0.107.79
CATEGORIES=	www dns
MASTER_SITES=	https://github.com/AdguardTeam/AdGuardHome/releases/download/v${PORTVERSION}/

MAINTAINER=	coreteam@freesense.org
COMMENT=	Pinned official AdGuard Home binary for FreeBSD
WWW=		https://adguard.com/adguard-home/overview.html

LICENSE=	GPLv3
LICENSE_FILE=	${WRKSRC}/LICENSE.txt

ONLY_FOR_ARCHS=	amd64 aarch64
CONFLICTS_INSTALL=	adguardhome

.if ${ARCH} == "aarch64"
DISTNAME=	AdGuardHome_freebsd_arm64
.else
DISTNAME=	AdGuardHome_freebsd_amd64
.endif

WRKSRC=		${WRKDIR}/AdGuardHome
NO_BUILD=	yes
NO_MTREE=	yes

PLIST_FILES=	bin/AdGuardHome

do-install:
	${MKDIR} ${STAGEDIR}${PREFIX}/bin
	${INSTALL_PROGRAM} ${WRKSRC}/AdGuardHome ${STAGEDIR}${PREFIX}/bin/AdGuardHome

.include <bsd.port.mk>
