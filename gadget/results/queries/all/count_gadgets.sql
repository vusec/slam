select count(*)
from (
	select entry_addr
	from translations
	group by entry_addr
)
