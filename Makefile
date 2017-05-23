# the extensions name
EXTENSION = check_chapmd5_password

# script files to install
DATA = check_chapmd5_password--0.0.1.sql

# our test script file (without extension)
REGRESS = check_chap_md5_test

MODULE_big = check_chapmd5_password
OBJS = check_chapmd5_password.o

# postgres build stuff
PG_CONFIG = pg_config
PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)
