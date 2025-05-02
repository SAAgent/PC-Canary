{
    # 1. 任务与试验标识
    "task_id": "string", # 任务唯一标识
    "task_name": "string", # 任务名称或简要描述
    "run_index": "integer", # 同一任务多次重复实验时的编号
    # 2. 整体结果（Outcome）
    "outcome": {
        "status": "enum[success, timeout, agent_error, env_error, incorrect_action, precondition_failure, aborted, unknown]",
        "agent_report_success": "boolean", # Agent 自报告是否成功
        "error": { # 仅在失败时填充
            "code": "string", # 统一错误码
            "message": "string", # 可读错误描述
            "source": "enum[agent, evaluator, app, env, unknown]"
        }
    },
    # 3. 性能指标（Performance）
    "performance": {
        "start_timestamp": "ISO8601", # 开始时间
        "end_timestamp": "ISO8601", # 结束时间
        "duration": "float", # 总耗时（秒）
        "agent_turns": "integer", # 与评估器交互轮次
        "llm_calls": "integer", # LLM 请求次数
        "resource_usage": { # 可选：运行时资源监控
            "cpu_peak_percent": "float",
            "mem_peak_mb": "float"
        }
    },
    # 4. 行为统计（Behavior）
    "behavior": {
        "tool_calls_total": "integer", # 高层工具/API 调用总次数
        "tool_calls_breakdown": { # 每种工具/API 的调用次数，仅为示例
            "click": 15,
            "type_text": 8,
            "search_contact": 2
        },
        "low_level_actions": "integer" # 底层实际交互动作总数（点击、键入等）
    },
    # 5. 正确性与质量（Correctness & Quality）
    "correctness": {
        # 关键步骤：总步骤数 & 完成数
        "steps_total": "integer", # 在 task config 中定义的步骤总数
        "steps_completed": "integer", # 实际完成的步骤数
        # 关键参数：总参数数 & 正确数
        "params_total": "integer", # 在 task config 中定义的参数总数
        "params_correct": "integer", # 实际使用正确的参数数
    },
    "quality": {
        "redundant_actions": "integer", # 明显错误或多余动作次数
        "custom_scores": { # 特定任务的额外质量分
            "search_relevance": 0.85
        }
    },
    # 6. 鲁棒性与错误处理（Robustness）
    "robustness": {
        "non_fatal_errors": "integer", # 非致命错误总数
        "error_events": [ # 详细错误日志
            {
                "code": "string",
                "message": "string",
                "source": "enum[agent, evaluator, app, env, unknown]",
                "timestamp_sec": "float" # 相对开始的秒数
            }
        ]
    }
}