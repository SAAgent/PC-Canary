#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import datetime
from enum import Enum
import datetime
from dataclasses import dataclass, field
from typing import Optional, List, Protocol,Tuple
import weakref
import json

    
class AnkiObj(Protocol):
    """鸭子类型：表示可以被 AnkiObjMap 管理的 Anki 对象"""
    def anki_hash(self) -> Tuple[str,str]:
        """返回对象的唯一哈希值"""
        ...
    
    @classmethod
    def generate_hash(cls, id:str) -> str:
        """生成 Note 的哈希值"""
        ...
class AnkiObjMap:
    _instance = None  # 单例模式
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(AnkiObjMap, cls).__new__(cls)
            cls._instance._map = {}  # 初始化映射
        return cls._instance
    
    def get(self, obj_hash: str) -> Optional[AnkiObj]:
        """通过哈希值获取对象"""
        return self._map.get(obj_hash)
    
    def add(self, obj: AnkiObj) -> None:
        """添加对象到映射中"""
        self._map[obj.anki_hash()] = obj
    
    def remove(self, obj_hash: str) -> None:
        """从映射中删除对象"""
        if obj_hash in self._map:
            del self._map[obj_hash]
    
    def clear(self) -> None:
        """清空所有映射的对象"""
        self._map.clear()
    
    def __len__(self) -> int:
        """返回映射中的对象数量"""
        return len(self._map)
    
    def __contains__(self, obj_hash: str) -> bool:
        """检查对象是否在映射中"""
        return obj_hash in self._map
   
    def array_by_type(self,type_:str) -> List[AnkiObj]:
        return [self._map[hash] for hash in self._map if hash[0] == type_ ]

class AnkiObjMixin:
    """为任何类提供 AnkiObj 协议所需的功能"""
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # 将对象注册到 AnkiObjMap
        AnkiObjMap().add(self)
        # 创建弱引用，在对象被销毁时自动从映射中移除
        self._finalizer = weakref.finalize(self, self._remove_from_map)
    
    def _remove_from_map(self):
        """当对象被垃圾回收时调用，从映射中移除自己"""
        AnkiObjMap().remove(self.anki_hash())
    
class CardType(Enum):
    NEW = 0          # 新卡
    LEARNING = 1     # 学习中
    REVIEW = 2       # 复习中
    RELEARNING = 3   # 重新学习

@dataclass
class Card(AnkiObjMixin):
    cid: int
    nid: int         # note id
    did: int         # deck id
    ord: int
    mod: datetime.datetime
    usn: int
    type: Optional[CardType]
    queue: int
    due: int
    ivl: int         # 间隔天数
    factor: int
    reps: int
    lapses: int
    left: int
    odue: int
    odid: int
    flags: int
    data: bytes
    
    def __post_init__(self):
        # 确保 AnkiObjMixin 的 __init__ 被调用
        super().__init__()
    
    @classmethod
    def from_row(cls, row: tuple) -> "Card":
        """row 是 (cid, nid, did, ord, mod, usn, type, queue, due, ivl, factor, reps, lapses, left, odue, odid, flags, data)"""
        try:
            card_type = CardType(row[6])
        except ValueError:
            card_type = None  # 遇到未知类型，避免崩掉
        return cls(
            cid=int(row[0]),
            nid=int(row[1]),
            did=int(row[2]),
            ord=int(row[3]),
            mod=datetime.datetime.fromtimestamp(row[4]),
            usn=int(row[5]),
            type=card_type,
            queue=int(row[7]),
            due=row[8],
            ivl=int(row[9]),
            factor=row[10],
            reps=row[11],
            lapses=row[12],
            left=row[13],
            odue=row[14],
            odid=row[15],
            flags=row[16],
            data=row[17]
        )
    
    def __repr__(self):
        return (f"<Card id={self.cid} nid={self.nid} did={self.did} "
                f"type={self.type.name if self.type else 'Unknown'} "
                f"mod={self.mod} ivl={self.ivl} days>")

    def anki_hash(self) -> Tuple[str,str]:
        return self.generate_hash(self.cid)
    @classmethod
    def generate_hash(cls, id:str) -> str:
        return ("card",f"{id}") 
    
    def get_note(self) -> Optional['Note']:
        """获取该卡片对应的笔记"""
        return AnkiObjMap().get(Note.generate_hash(self.nid))
    
    def get_deck(self) -> Optional['Deck']:
        """获取该卡片所属的牌组"""
        return AnkiObjMap().get(Deck.generate_hash(self.did))
@dataclass
class Note(AnkiObjMixin):
    
    nid: int
    guid: str
    mid: int
    mod: datetime.datetime
    usn: int
    tags: List[str]
    fields: List[str]
    sfld: str
    flags: int
    data: bytes
    US: str = field(default="\x1f", repr=False, init=False) 
    @classmethod
    def from_row(cls, row: tuple) -> "Note":
        """row 是 (nid, guid, mid, mod, usn, tags, flds, sfld, csum, flags, data)"""
        # === tags：去首尾空格 → 按空格切分 → 去掉空串 ===
        raw_tags = row[5].strip()
        tags = [t for t in raw_tags.split(" ") if t] if raw_tags else []
        
        # === flds：用 \x1f 分隔得到字段列表 ===
        fields = row[6].split(cls.US)
        
        return cls(
            nid=int(row[0]),
            guid=row[1],
            mid=int(row[2]),
            mod=datetime.datetime.fromtimestamp(row[3]),
            usn=int(row[4]),
            tags=tags,
            fields=fields,
            sfld=row[7],
            flags=int(row[9]),
            data=row[10]
        )
    
    def __repr__(self) -> str:
        first = self.fields[0] if self.fields else ""
        return (f"<Note id={self.nid} mid={self.mid} "
                f"tags={self.tags} mod={self.mod.isoformat()} "
                f"first_field={first!r}>")

    def __post_init__(self):
        # 确保 AnkiObjMixin 的 __init__ 被调用
        super().__init__()
    
    def anki_hash(self) -> Tuple[str,str]:
        return self.generate_hash(self.nid)
    
    @classmethod
    def generate_hash(cls, id:str) -> str:
        return ("note",f"{id}")
    
@dataclass
class Deck(AnkiObjMixin):
    did: int
    name: str
    mtime: datetime.datetime
    usn: int
    common_raw: bytes
    kind_raw: bytes
    common: Optional[object] = None   # 解析后对象或 None
    kind:   Optional[object] = None

    @classmethod
    def from_row(cls, row: tuple) -> "Deck":
        """row 是 (id, name, mtime_secs, usn, common, kind)"""
        _id, _name, _mtime, _usn, _common, _kind = row

        # 转时间
        mtime_dt = datetime.datetime.fromtimestamp(_mtime)

        common_obj, kind_obj = None, None

        return cls(
            did=int(_id),
            name=_name,
            mtime=mtime_dt,
            usn=int(_usn),
            common_raw=_common,
            kind_raw=_kind,
            common=common_obj,
            kind=kind_obj,
        )

    # 友好展示
    def __repr__(self):
        typ = "Filtered" if getattr(self.kind, "filtered", False) else "Normal"
        return (f"<Deck id={self.did} name='{self.name}' "
                f"type={typ} mtime={self.mtime.isoformat()} "
                f"limits=new:{self.common.new_per_day if self.common else '?'} "
                f"rev:{self.common.review_per_day if self.common else '?'}>")
    
    def __post_init__(self):
        # 确保 AnkiObjMixin 的 __init__ 被调用
        super().__init__()
    
    def anki_hash(self) -> Tuple[str,str]:
        return self.generate_hash(self.did)
    
    @classmethod
    def generate_hash(cls,id:str) -> str:
        return ("deck",f"{id}")

@dataclass
class Collection(AnkiObjMixin):
    id: int
    crt: datetime.datetime
    mod: datetime.datetime
    scm: int

    def __post_init__(self):
        super().__init__()

    @classmethod
    def from_row(cls, row: tuple) -> "Collection":
        """row 是 (id, crt, mod, scm, vers)"""
        return cls(
            id=row[0],
            crt=datetime.datetime.fromtimestamp(int(row[1])),
            mod=datetime.datetime.fromtimestamp(int(row[2]) / 1000),
            scm=row[3]
        )

    def __repr__(self):
        return (f"<Collection id={self.id} ver={self.ver} mod={self.mod.isoformat()}")

    def anki_hash(self) -> Tuple[str, str]:
        return self.generate_hash(self.id)

    @classmethod
    def generate_hash(cls, id: int) -> Tuple[str, str]:
        return ("col", f"{id}")

@dataclass
class Tag(AnkiObjMixin):
    tag: str
    usn: int

    def __post_init__(self):
        super().__init__()

    @classmethod
    def from_row(cls, row: tuple) -> "Tag":
        """row 是 (tag, usn, collapsed, config)"""
        return cls(
            tag=row[0],
            usn=row[1],

        )

    def __repr__(self):
        return f"<Tag tag={self.tag} usn={self.usn}>"

    def anki_hash(self) -> Tuple[str, str]:
        return self.generate_hash(self.tag)
    
    @classmethod
    def generate_hash(cls, id: int) -> Tuple[str, str]:
        return ("tag", f"{id}")
