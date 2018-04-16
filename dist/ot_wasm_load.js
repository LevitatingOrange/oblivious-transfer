const supported = (() => {
    try {
        if (typeof WebAssembly === "object" &&
            typeof WebAssembly.instantiate === "function") {
            const module = new WebAssembly.Module(Uint8Array.of(0x0, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00,
                0x00));
            if (module instanceof WebAssembly.Module)
                return new WebAssembly.Instance(module) instanceof WebAssembly.Instance;
        }
    } catch (e) {}
    return false;
})();

if (supported) {
    WebAssembly.instantiateStreaming(fetch('ot.wasm'))
        .then(wasm_module => {
            alert(`2 + 1 = ${wasm_module.instance.exports.add_one(2)}`);
        });
} else {
    alert("This demo needs web assembly. Use a recent browser!");
}