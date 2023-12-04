select min_insts, count(*) as total
from (
	select entry_addr, min(number_of_insts) as min_insts
	from translations
	group by entry_addr
)
group by min_insts
order by min_insts
