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
