#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from typing import Dict, Any, Optional, List

# Track filter-related states
_FILTERS_ADDED = set()
_FILTERS_ENABLED = set()
_FILTERS_DISABLED = set()
_FILTERS_REMOVED = set()

filters_added = False
filters_enabled_disabled = False
filters_removed = False


def message_handler(
    message: Dict[str, Any], logger, task_parameter: Dict[str, Any]
) -> Optional[List[Dict[str, Any]]]:
    global filters_added, filters_enabled_disabled, filters_removed
    payload = message["payload"]
    print(payload)
    event_type = payload["event"]
    logger.debug(f"Received event: {event_type}")
    """
    Handle messages received from the hook script
    
    Args:
        message: Injector message object
        data: Additional data
        
    Returns:
        str: Returns "success" if the task is successfully completed, otherwise returns None
    """
    global _FILTERS_ADDED, _FILTERS_ENABLED, _FILTERS_DISABLED, _FILTERS_REMOVED

    # Get expected filter information
    expected_filters = []
    filter_types_map = {}  # Used to store the mapping of filter names and types

    expected_filters = [
        filter_info["name"] for filter_info in task_parameter["filters"]
    ]

    # Create a mapping of filter names to filter types
    for filter_info in task_parameter["filters"]:
        filter_types_map[filter_info["name"]] = filter_info["type"]

    # Handle events sent from hooker.js
    payload = message.get("payload", {})
    event_type = payload.get("event")

    logger.info(f"Received event: {event_type}, payload: {payload}")

    if event_type == "filter_created":
        filter_name = payload.get("filterName")
        source_name = payload.get("sourceName")
        filter_kind = payload.get("filterKind")

        if filter_name in expected_filters:
            # Check if the filter type matches
            expected_type = filter_types_map.get(filter_name)

            if expected_type and filter_kind:
                if expected_type in filter_kind or filter_kind in expected_type:
                    logger.info(
                        f"Filter '{filter_name}' type matched successfully: Expected '{expected_type}', Actual '{filter_kind}'"
                    )
                    _FILTERS_ADDED.add(filter_name)
                    logger.info(
                        f"Filter '{filter_name}' has been added to source '{source_name}'"
                    )
                else:
                    logger.warning(
                        f"Filter '{filter_name}' type does not match: Expected '{expected_type}', Actual '{filter_kind}'"
                    )
            else:
                # If there is no type information, check based on name only
                _FILTERS_ADDED.add(filter_name)
                logger.info(
                    f"Filter '{filter_name}' has been added to source '{source_name}', but type check was not performed"
                )

            # Check if all filters have been added
            if all(filter_name in _FILTERS_ADDED for filter_name in expected_filters):
                logger.info("All filters have been successfully added")
                filters_added = True
                return [{"status": "key_step", "index": 1}]

    elif event_type == "filter_enabled":
        filter_name = payload.get("filterName")
        if filter_name in expected_filters:
            _FILTERS_ENABLED.add(filter_name)
            logger.info(f"Filter '{filter_name}' has been enabled")

            # Check enable and disable conditions
            return check_enable_disable_status(logger, task_parameter)

    elif event_type == "filter_disabled":
        filter_name = payload.get("filterName")
        if filter_name in expected_filters:
            _FILTERS_DISABLED.add(filter_name)
            logger.info(f"Filter '{filter_name}' has been disabled")

            # Check enable and disable conditions
            return check_enable_disable_status(logger, task_parameter)

    elif event_type == "filter_removed":
        filter_name = payload.get("filterName")

        if filter_name in expected_filters:
            _FILTERS_REMOVED.add(filter_name)
            logger.info(f"Filter '{filter_name}' has been removed")

            # Check if all filters have been removed
            if all(filter_name in _FILTERS_REMOVED for filter_name in expected_filters):
                logger.info("All filters have been successfully removed")
                filters_removed = True
                # Check if the task is completed
                if check_task_completed():
                    return [
                        {"status": "key_step", "index": 3},
                        {
                            "status": "success",
                            "reason": "Add, enable/disable, and remove filter operations completed",
                        },
                    ]
    return None


def check_enable_disable_status(
    logger, task_parameter
) -> Optional[List[Dict[str, Any]]]:
    """Check the enable and disable status of filters"""
    global _FILTERS_ENABLED, _FILTERS_DISABLED, filters_enabled_disabled

    expected_filters = []
    expected_filters = [
        filter_info["name"] for filter_info in task_parameter["filters"]
    ]

    # Check if each filter has been enabled and disabled
    if all(filter_name in _FILTERS_ENABLED for filter_name in expected_filters) and all(
        filter_name in _FILTERS_DISABLED for filter_name in expected_filters
    ):
        logger.info("All filters have been successfully enabled and disabled")
        filters_enabled_disabled = True
        return [{"status": "key_step", "index": 2}]
    return None


def check_task_completed():
    """Check if the task is completed"""
    global filters_added, filters_enabled_disabled, filters_removed
    # Check all success conditions
    is_completed = filters_added and filters_enabled_disabled and filters_removed

    return is_completed
