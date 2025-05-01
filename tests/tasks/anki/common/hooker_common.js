//! The script only tested in x86-64!
const BASE = Process.getModuleByName("librsbridge.so").base;
// the function address to trace, and its name

function _sendEvent(eventType, messagedata = {}, data = null) {
    const message = {
        type: eventType,
        ...messagedata,
        timestamp: new Date().getTime()
    };
    send(message, data);
}

function read_rust_i64(ptr) {
    var byteArray = ptr.readByteArray(8);  // i64需要8字节

    // 将字节数组转换为大端法的i64值
    var value = 0;
    for (var i = 0; i < 8; i++) {
        value = (value << 8) | byteArray[i];
    }

    // 处理符号位
    if (value > 0x7FFFFFFFFFFFFFFF) {
        value = value - 0x10000000000000000;
    }
    return value
}

function sendEvent(message = {}, data = null) {
    _sendEvent("trace", message, data);
}

function sendLog(level, msg) {
    _sendEvent("log", { "level": level, "msg": msg });
}

function initHook(function_name, config) {
    Interceptor.attach(BASE.add(config.addr), {
        onEnter: function () {
            const isArm64 = Process.arch === "arm64";
            const argRegs = isArm64 ? ["x0", "x1", "x2", "x3", "x4"] : ["rdi", "rsi", "rdx", "rcx", "r8"];
            this.savedArgs = {};
            for (let i = 0; i < argRegs.length; i++) {
                let reg = argRegs[i];
                this.savedArgs[i] = this.context[reg];  // 保存成 savedArgs[0], savedArgs[1], ...
            }
        },
        onLeave: function (retval) {
            // if (config["post_handler"]) {
            // result = config.post_handler(this.savedArgs[0], this.savedArgs[1],this.savedArgs[2],this.savedArgs[3]);
            // console.log(result.cid)
            // console.log(function_name);
            // }
            sendEvent({ "function": function_name });
        }
    });
    sendLog("info", `hook ${function_name} at ${config.addr.toString(16)}`);
}

const TRACE_MAPS = {
        "storage_add_card": {
            "addr": 0x00000000007065a0,
        },
        "storage_update_card": {
            "addr": 0x0000000000705e40,
            "filter" : "anki::storage::card::<impl anki::storage::sqlite::SqliteStorage>::update_card"
        },
        "storage_add_note": {
            "addr": 0x000000000071ec60,
        },
        // "storage_get_note" : 0x000000000071e0b0,
        "storage_update_note": {
            "addr": 0x000000000071e660,
        },
        "storage_add_deck" : {
            "addr": 0x00000000007131c0,
            "filter" : "anki::storage::deck::<impl anki::storage::sqlite::SqliteStorage>::add_deck$"
        },
        "storage_remove_deck" : {
            "addr": 0x0000000000714450,
            "filter" : "anki::storage::deck::<impl anki::storage::sqlite::SqliteStorage>::remove_deck$"
        },
        "service_undo" : {
            "addr" : 0x0000000000c5ea30,
            "filter" : "anki::services::<impl anki::backend::Backend>::undo$"
        },
        "service_serach_cards" : {
            "addr" : 0x0000000000c80ca0,
            "filter" : "anki::services::<impl anki::backend::Backend>::search_cards$"
        },
        "service_clear_unused_tags" : {
            "addr" : 0x0000000000492a70,
            "filter" : "anki::tags::service::<impl anki::services::TagsService for anki::collection::Collection>::clear_unused_tags$"
        }
};