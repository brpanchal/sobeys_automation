from dataclasses import dataclass, field
from typing import Optional

@dataclass
class B2BCodeListEntry:
    senderCode: str = field(default="")
    receiverCode: str = field(default="")
    description: str = field(default="")
    text1: Optional[str] = field(default="")
    text2: Optional[str] = field(default="")
    text3: Optional[str] = field(default="")
    text4: Optional[str] = field(default="")
    text5: Optional[str] = field(default="")
    text6: Optional[str] = field(default="")
    text7: Optional[str] = field(default="")
    text8: Optional[str] = field(default="")
    text9: Optional[str] = field(default="")
    id: Optional[str] = field(default="")

    def to_dict(self):
        payload = {
            "codes": [
                {
                    "senderCode": f"{self.senderCode}",
                    "receiverCode": f"{self.receiverCode}",
                    "description": f"{self.description}",
                    "text1": f"{self.text1 if self.text1 else ''}",
                    "text2": f"{self.text2 if self.text2 else ''}",
                    "text3": f"{self.text3 if self.text3 else ''}",
                    "text4": f"{self.text4 if self.text4 else ''}",
                    "text5": f"{self.text5 if self.text5 else ''}",
                    "text6": f"{self.text6 if self.text6 else ''}",
                    "text7": f"{self.text7 if self.text7 else ''}",
                    "text8": f"{self.text8 if self.text8 else ''}",
                    "text9": f"{self.text9 if self.text9 else ''}",
                }
            ]
        }
        return payload
