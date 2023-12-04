select entry_addr, min(number_of_insts) as min_insts
from translations
group by entry_addr
