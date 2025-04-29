import os
import time
from typing import Dict, Any, Callable,Tuple,List
import sqlite3
import shutil
import os
import tempfile
from enum import Enum
from .orm import AnkiObjMap,Deck,Note,Card

class FridaEvent:
    def __init__(self,key,value):
        self.key = key
        self.value = value
    
    def __repr__(self):
        return f"Event(key={self.key}, value={self.value})"
    
    def describe(self):
        pass
     
    def into_metric(self) -> Tuple[Any, Any]:
        return (self.key,self.value)
        

class StatusType(Enum):
    SUCCESS = "success"
    PROGRESS = "progress"
    ERROR = "error"
    NONE = None
    
class Status:
    def __init__(self,metric:List[FridaEvent]=None,status:StatusType = StatusType.NONE):
        self.metric = metric if metric is not None else []
        self.status = status
        
    def emit(self,metric:FridaEvent):
        self.metric.append(metric) 
    
    def mark_success(self):
        self.status = StatusType.SUCCESS
    
    def mark_progress(self):
        self.status = StatusType.PROGRESS
        
    def mark_error(self):
        self.status = StatusType.ERROR 
class Context:
    def __init__(self,evaluator):
        self.evaluator = evaluator
        sql_path = evaluator.config["sql_path"]
        self.config = evaluator.config
        self.sql_path = sql_path
        if not os.path.exists(sql_path):
            raise FileNotFoundError(f"Database file not found at {sql_path}")
        self.start_time = time.time() 
        self.tmpdirname = tempfile.mkdtemp()
        self.trace_handlers = {}
        self.log("info",f"tmp path={self.tmpdirname}")
        

    def query(self,sql:str):
        cur = self.conn.cursor()
        cur.execute(sql)
        return cur.fetchall()
   
    def update_database(self):
        self.cards = None
        self.notes = None
        self.decks = None
        AnkiObjMap().clear()
        self._load_snapshot()

    def _load_snapshot(self):
        dst_file = shutil.copy(self.sql_path, self.tmpdirname)
        _dst_file2 = shutil.copy(self.sql_path+"-wal", self.tmpdirname)

        try:
           self.conn = sqlite3.connect(f'file:{dst_file}', uri=True)
        except Exception as e:
            shutil.rmtree(self.tmpdirname)
            raise e 
        cur = self.conn.cursor()
        cur.execute("SELECT * FROM cards;")
        self.cards = [Card.from_row(i) for i in cur.fetchall()]
        cur.execute("SELECT * FROM notes;")
        self.notes = [Note.from_row(i) for i in cur.fetchall()]
        cur.execute("SELECT * FROM decks;")
        self.decks = [Deck.from_row(i) for i in cur.fetchall()]

        
    def __del__(self):
        if self.conn:
            self.conn.close()
        if os.path.exists(self.tmpdirname):
            shutil.rmtree(self.tmpdirname)
        
    def register_trace_handlers(self, handlers: Dict[str, Callable]):
        for function_name, handler in handlers.items():
            self.trace_handlers[function_name] = handler    
    
    def handle_trace(self,function_name,message,data) -> str:
        if function_name in self.trace_handlers:
            result : Status = self.trace_handlers[function_name](self,message,data)
            for v in result.metric: 
                key,value = v.into_metric()
                self.evaluator.update_metric(key,value)
            if result.status:
                return result.status.value
        else:
            self.log("error",f"Trace handler for {function_name} not found")
        return None

    def log(self, level,msg):
        match level:
            case "info":
                self.evaluator.logger.info(msg)
            case "error":
                self.evaluator.logger.error(msg)


    def get_current_time_used(self):
        return time.time() - self.start_time