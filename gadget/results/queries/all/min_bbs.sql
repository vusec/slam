select entry_addr, min(number_of_bbs) as min_bbs
from translations
group by entry_addr
