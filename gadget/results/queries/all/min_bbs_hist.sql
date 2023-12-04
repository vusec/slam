select min_bbs, count(*) as count
from (
	select entry_addr, min(number_of_bbs) as min_bbs
	from translations
	group by entry_addr
)
group by min_bbs
order by min_bbs
