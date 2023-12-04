select min_insts, count(*) as simple
from (
	select entry_addr, min(number_of_insts) as min_insts
	from translations
	where simple_trans=1 and number_of_bbs=1
	group by entry_addr
)
group by min_insts
order by min_insts
