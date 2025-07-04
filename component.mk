# Include directories relative to the component directory
COMPONENT_ADD_INCLUDEDIRS:=libssh2/src libssh2/include .

# Source directories (all .c files in these directories will be compiled)
COMPONENT_SRCDIRS:=libssh2/src

# Required components
COMPONENT_DEPENDS:=mbedtls tcpip_adapter

# Compiler flags
CFLAGS+=-Wno-error=format
CFLAGS+=-Wno-error=maybe-uninitialized
CFLAGS+=-Wno-error=uninitialized
CFLAGS+=-Wno-error=narrowing

# Crypto engine configuration
CFLAGS+=-DLIBSSH2_MBEDTLS

# Debug logging configuration
CFLAGS+=-DLIBSSH2DEBUG
