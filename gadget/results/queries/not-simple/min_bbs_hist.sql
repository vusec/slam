select min_bbs, count(*) as not_simple
from (
	select entry_addr, min(number_of_bbs) as min_bbs
	from translations
	where not(simple_trans=1 and number_of_bbs=1)
	group by entry_addr
)
group by min_bbs
order by min_bbs
