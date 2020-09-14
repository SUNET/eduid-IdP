SOURCE=	src
EDUIDCOMMON= ../eduid-common/src
EDUIDUSERDB= ../eduid-userdb/src

test:
	pytest

reformat:
	isort --line-width 120 --atomic --project eduid_webapp --recursive $(SOURCE)
	black --line-length 120 --target-version py37 --skip-string-normalization $(SOURCE)

typecheck:
	mypy --ignore-missing-imports $(SOURCE)

typecheck_extra:
	mypy --ignore-missing-imports $(EDUIDCOMMON) $(EDUIDUSERDB) $(SOURCE)
