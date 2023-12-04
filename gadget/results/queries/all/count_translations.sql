select count(*)
from (
	select entry_addr, translation_addr
	from translations
	group by entry_addr, translation_addr
)
