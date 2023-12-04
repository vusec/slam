select attacker_registers, count(*) as total
from (
	select attacker_registers, entry_addr
	from translations
	group by attacker_registers, entry_addr
)
group by attacker_registers
order by total ASC