select type, count(*)
from (
	select entry_addr, type
	from translations
	group by entry_addr, type
)
group by type
