# Todo: Generate through cmakelists.txt
PYTHON_MAJOR_V = 3
PYTHON_VERSION = 3.6
PYTHON_INCLUDE = /usr/include/python$(PYTHON_VERSION)
PYTHON_CONFIG = $(shell python$(PYTHON_VERSION)-config --configdir)
BOOST_INC = /usr/include
BOOST_LIB = /usr/lib
TARGET = CryptPy
$(TARGET).so: $(TARGET).o
	g++ -shared -Wl,--export-dynamic $(TARGET).o -L$(BOOST_LIB) -lboost_python$(PYTHON_MAJOR_V) -L$(PYTHON_CONFIG) -lpython$(PYTHON_VERSION) -lCrypt -o $(TARGET).so
$(TARGET).o: $(TARGET).cpp
	g++ -I$(PYTHON_INCLUDE) -I$(BOOST_INC) -lCrypt -fPIC -c $(TARGET).cpp
.PHONY: install
install:
	install -m 557 CryptPy.o CryptPy.so $(shell python3 -m site --user-site)