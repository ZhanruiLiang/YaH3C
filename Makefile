prefix= /home/${SUDO_USER}/.yah3c

all:
	python setup.py build

install:
	python setup.py install 
	if [ -e ${prefix} ];  \
		then \
			echo "${prefix} already exist.";\
		else\
			mkdir ${prefix}; \
			cp -r ./yah3c/plugins yah3crc.py -d ${prefix};\
			chown ${SUDO_USER} -R ${prefix}; \
		fi

