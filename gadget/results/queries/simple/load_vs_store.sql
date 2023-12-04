select type, count(*)
from (
	select entry_addr, type
	from translations
	where simple_trans=1 and number_of_bbs=1
	group by entry_addr, type
)
group by type
