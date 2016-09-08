# Determine directory of this file.
THIS_MAKEFILE := $(word $(words $(MAKEFILE_LIST)), $(MAKEFILE_LIST))
THIS_DIR := $(shell cd $(dir $(THIS_MAKEFILE)); pwd)

# Libressl should reside in the platform dir
LIBRESSL := $(THIS_DIR)/../../../libressl

TARGET= [target]

XINCLUDES=	[includes] -I$(LIBRESSL)/dist/include
XLDFLAGS=	-L$(LIBRESSL)/dist/lib -Wl,--no-as-needed -lrt -Wl,-Bstatic -ltls -lcrypto -lssl -Wl,-Bdynamic -lrt

Makefile : $(LIBRESSL)/dist/lib/libtls.a


#libressl/dist/lib/libtls.a:
# insert-stable-version-here

.NOTPARALLEL : $(LIBRESSL)/dist/lib/libtls.a

$(LIBRESSL)/dist/lib/libtls.a:
	$(SHELL) -ec "\
	  [ -d $(LIBRESSL)/.git ] || git clone https://github.com/libressl-portable/portable.git $(LIBRESSL) ;\
	  cd $(LIBRESSL);\
	  [ -d dist ] || mkdir -p dist;\
	  export CC_FOR_BUILD=\"$(CC)\" HOST_CC=\"$(CC)\" CC=\"$(CC)\" CXX=\"$(CXX)\" prefix=$(LIBRESSL)/dist MAKEFLAGS= ;\
	  ./autogen.sh ;\
	  ./configure --disable-shared --enable-static --prefix=$(LIBRESSL)/dist ;\
	  make install"
