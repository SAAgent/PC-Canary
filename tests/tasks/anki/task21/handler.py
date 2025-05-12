#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import sys
import os
sys.path.append(os.path.dirname(__file__))
from common import *
import re


def check_html_for_valid_styled_span(html_string: str) -> bool:
    # 1. 定义颜色值的模式 (rgb(...) 或 颜色名)
    #    - rgb\s*\(\s*\d+\s*,\s*\d+\s*,\s*\d+\s*\) : 匹配rgb格式，忽略各部分之间的空格
    #      \s* 代表零个或多个空格
    #      \d+ 代表一个或多个数字
    #    - [a-zA-Z]+ : 匹配一个或多个英文字母 (颜色名)
    color_value_pattern = r"(?:rgb\s*\(\s*\d+\s*,\s*\d+\s*,\s*\d+\s*\)|[a-zA-Z]+)"
    # 2. 构建完整的<span>标签匹配模式
    #    - <\s*span\s+ : 匹配 "<span " (span前后允许空格，之后至少一个空格)
    #    - [^>]*?       : 非贪婪匹配任何非'>'字符 (用于span标签内，style属性前的其他属性)
    #    - style\s*=\s*" : 匹配 "style=" (等号前后允许空格) 和开始的引号
    #      Inside the style attribute's value:
    #      - [^"]*?    : 非贪婪匹配引号内，'color:'声明之前的任何字符 (其他CSS属性)
    #      - color\s*:\s* : 匹配 "color:" (冒号前后允许空格)
    #      - (our color_value_pattern) : 嵌入上面定义的颜色值模式
    #      - \s* : 匹配颜色值之后可能存在的空格 (在分号或引号前)
    #      - [^"]*?    : 非贪婪匹配引号内，颜色值之后到结束引号前的任何字符 (其他CSS属性或分号)
    #    - "             : 匹配style属性的结束引号
    #    - [^>]*?       : 非贪婪匹配任何非'>'字符 (用于span标签内，style属性后的其他属性)
    #    - >             : 匹配span开始标签的结束尖括号
    #    - .*?           : 非贪婪匹配span标签内的任何内容
    #    - <\s*/\s*span\s*> : 匹配 "</span>" (标签名内外允许空格)

    # (?i) 代表 re.IGNORECASE, (?s) 代表 re.DOTALL
    # 使用 (?i) 使匹配对大小写不敏感 (span, style, color)
    # 使用 (?s) 使 . 可以匹配包括换行符在内的任何字符 (用于span标签内容)
    # 在Python中，我们通常在 re.search 或 re.compile 中传递标志参数
    
    full_span_pattern = (
        r'<\s*span\s+'                                  # <span (tag name itself is case-insensitive due to flag)
        r'[^>]*?'                                       # Attributes before style (non-greedy)
        r'style\s*=\s*"'                                # style="
        r'[^"]*?'                                       # CSS properties before 'color:' (non-greedy)
        r'color\s*:\s*' + color_value_pattern +         # 'color:' followed by the valid color value
        r'\s*'                                          # Optional spaces after the color value (e.g., before a semicolon or quote)
        r'[^"]*?"'                                      # Other CSS properties after 'color:' and the closing quote of style
        r'[^>]*?>'                                      # Attributes after style, and the closing > of the span tag
        r'.*?'                                          # Content inside the span (non-greedy)
        r'<\s*/\s*span\s*>'                             # </span>
    )

    # re.IGNORECASE 使标签名(span)、属性名(style)、CSS属性名(color)不区分大小写
    # re.DOTALL 使点(.)能匹配包括换行符在内的所有字符 (主要影响 .*? 来匹配标签内容)
    if re.search(full_span_pattern, html_string, re.IGNORECASE | re.DOTALL):
        return True
    return False 


def handle_storage_add_card(context: Context,message) -> Status:
    context.update_database()
    latest : Card = sorted(AnkiObjMap().array_by_type("card"),key=lambda x: x.mod,reverse=True)[0]
    note = latest.get_note()
    status = Status(status=StatusType.PROGRESS)
    status.emit(EventCardAdded())
    if len(note.fields) != 2:
        return status

    first_field = 'To <span style="color: rgb(255, 0, 0);">be</span> or <span style="color: rgb(255, 0, 0);">not to be</span>'
    second_field = "that's a question"
    
    if check_html_for_valid_styled_span(note.fields[0]) and note.fields[1] == second_field and len(note.tags) == 1 and note.tags[0] == "quote":
        status.emit(EventCorrectField())
        status.emit(EventCorrectFormat())
    elif second_field == note.fields[1] and "To" in note.fields[0] and "be" in note.fields[0] and "not to be" in note.fields[0]:
        status.emit(EventCorrectField())
        status.emit(EventWrongFormat(f"{note.fields[0]}",first_field))
    else:
        status.emit(EventWrongField(note.fields,f"[{first_field} {second_field}]"))
    return status
      
TRACE_HANDLERS = {
    "storage_add_card": handle_storage_add_card
}   
dependency_graph = {
    card_added_ : [],
    correct_field_ : [card_added_],
    wrong_field_ : [card_added_],
    correct_format_ : [card_added_],
    wrong_format_ : [card_added_]
}
finished_list = [
    correct_field_,correct_format_
]

bind_handlers(TRACE_HANDLERS,dependency_graph,finished_list)