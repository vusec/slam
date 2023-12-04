select count(*)
from (
	select entry_addr
	from translations
	inner join ibts
	on translations.label=ibts.function
	group by entry_addr
)
