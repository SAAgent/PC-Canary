import os
import time
from typing import Dict, Any, Callable, Optional,Tuple,List
import sqlite3
import shutil
import os
import tempfile
from enum import Enum
from .orm import AnkiObjMap,Deck,Note,Card,Collection
import json

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
        
class EventMonitor:
    def __init__(self, dependency_graph: Dict[str, List[str]], finish_events : List[str]):
        # 依赖关系图：键是事件名，值是该事件依赖的事件列表
        self.dependency_graph = dependency_graph
        self.allow_triggered_events: set = set()  # 已触发的事件
        self.triggered_events: set = set()  # 已触发的事件
        self.waiting_for: Dict[str, List[str]] = {}  # 记录哪些事件在等待哪些依赖
        self.finished_events = finish_events

        # 初始化依赖关系
        for event, dependencies in self.dependency_graph.items():
            for dep in dependencies:
                if dep not in self.waiting_for:
                    self.waiting_for[dep] = []
                self.waiting_for[dep].append(event)
            if not dependencies:
                self.allow_triggered_events.add(event)
    def trigger_event(self, event: FridaEvent):
        """触发事件并检查是否可以触发其他依赖该事件的事件"""
        event = event.key
        if event not in self.allow_triggered_events:
            return
        
        # 触发当前事件
        self.triggered_events.add(event)
        
        # 检查是否有事件可以被触发
        if event in self.waiting_for:
            for dependent_event in self.waiting_for[event]:
                # 检查所有依赖事件是否已触发
                if all(dep in self.triggered_events for dep in self.dependency_graph[dependent_event]):
                    self.allow_triggered_events.add(dependent_event)

    def get_triggered_events(self):
        return self.triggered_events

    def is_finished(self):
        return all([condition in self.triggered_events for condition in self.finished_events])

    def is_event_triggered(self,event:FridaEvent):
        return event.key in self.triggered_events

    def should_event_trigger(self,event:FridaEvent):
        return event.key in self.allow_triggered_events
    
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
    def __init__(self,evaluator,dependency_graph:Dict[str,List[str]],finished_events:List[str]):
        self.evaluator = evaluator
        sql_path = evaluator.config["sql_path"]
        self.config = evaluator.config
        self.sql_path = sql_path
        if not os.path.exists(sql_path):
            raise FileNotFoundError(f"Database file not found at {sql_path}")
        self.start_time = time.time() 
        self.tmpdirname = tempfile.mkdtemp()
        self.trace_handlers = {}
        self.monitor = EventMonitor(dependency_graph,finished_events)
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

    def _load_snapshot(self,ref_time=None):
        if os.path.exists(os.path.join(self.tmpdirname,"collection.anki2")):
            os.unlink(os.path.join(self.tmpdirname,"collection.anki2"))
        if os.path.exists(os.path.join(self.tmpdirname,"collection.anki2-wal")):
            os.unlink(os.path.join(self.tmpdirname,"collection.anki2-wal"))
        dst_file = shutil.copy(self.sql_path, self.tmpdirname)
        time.sleep(0.3)
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
        cur.execute("SELECT * FROM config;")
        self.anki_config = {}
        for t in cur.fetchall():
            self.anki_config[t[0]] = t[3]

        
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
            result : Optional[Status] = self.trace_handlers[function_name](self,message,data)
            if not (result and isinstance(result,Status)):
                return None
            for v in result.metric: 
                self.monitor.trigger_event(v)
                if self.monitor.is_finished():
                    result.mark_success()
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

    def should_event_trigger(self,event: FridaEvent):
        return self.monitor.should_event_trigger(event)