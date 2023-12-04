select attacker_registers, count(*) as total_indirect
from (
	select attacker_registers, entry_addr
	from translations
	where simple_trans=1 and number_of_bbs=1 and chain_depth_max>=2
	group by attacker_registers, entry_addr
)
group by attacker_registers
order by total_indirect ASC