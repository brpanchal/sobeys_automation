from dataclasses import dataclass, field
from typing import List
from app.models.b2b_codelist_entry import B2BCodeListEntry

@dataclass
class B2BCodelist:
    id: str
    codeListName: str
    versionNumber: int
    createDate: str
    userName: str
    listStatus: int
    codes: List[B2BCodeListEntry] = field(default_factory=list)
