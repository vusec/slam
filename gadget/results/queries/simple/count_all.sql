select count(*)
from (
	select *
	from translations
	where simple_trans=1 and number_of_bbs=1
)
