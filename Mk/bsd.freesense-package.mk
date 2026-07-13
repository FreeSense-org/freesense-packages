# Central compatibility contract for optional FreeSense packages.
# Included automatically by the FreeSense ports overlay helper for every
# FreeSense-pkg-* origin, keeping the ABI binding impossible to forget when a
# new integration is added.

.if !defined(_FREESENSE_PACKAGE_MK_INCLUDED)
_FREESENSE_PACKAGE_MK_INCLUDED=	yes

# Official builds always inject the train derived from src/etc/version. The
# fail-closed fallback prevents an ad-hoc port build from silently claiming
# compatibility with a real release train.
FREESENSE_PACKAGE_TRAIN?=	0.0
RUN_DEPENDS+=	FreeSense-platform-abi=${FREESENSE_PACKAGE_TRAIN}.0:sysutils/FreeSense-platform-abi

.endif
