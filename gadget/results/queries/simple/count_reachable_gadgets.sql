select count(*)
from (
	select entry_addr
	from translations
	inner join ibts
	on translations.label=ibts.function
	where simple_trans=1 and number_of_bbs=1
	group by entry_addr
)
