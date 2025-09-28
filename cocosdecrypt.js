function hookDecryptFunction(module, ghidraAddress) {
    let addr = module.add(ghidraAddress - 0x00100000)  //Assumes ghidra base address as 00100000, hence offset is calculated from that

    Interceptor.attach(addr, {
        onEnter: function(args) {
            var decrypt_key =args[2].readCString(); // Decrypt_Key
            // Send key to python script
            send({
                type: 'DECRYPT_KEY',
                key: decrypt_key
            })
        },

        onLeave: function(retval) {
            // Optional Dump Output.
            // console.log(Memory.readUtf8String(retval));
        }
    });
}

function hookCocosCreatorDecrypt(func_address) {
    let address = func_address //0x00d69db4  #addess of the xxtea_decrypt function 
    let soName = 'libcocos.so'
    let baseAddr = Module.findBaseAddress(soName)

    // The below code will look for the so file being loaded if
    // it is not already loaded
    if (baseAddr != null) {
        // console.log("Cocos Creator module present: ");
        hookDecryptFunction(baseAddr, address)
    } else {
        // console.log("Waiting for cocos creator");
        var hasFoundIt = false
        Interceptor.attach(Module.findExportByName("libc.so", "open"), {
            onEnter: function(args) {
                var str = args[0].readUtf8String();
                if (hasFoundIt) return;
                if (str.includes(soName)) {
                    var test2 = Module.findBaseAddress(soName)
                    if (test2 != null) {
                        hasFoundIt = true;
                        // console.log("Found Cocos Creator Module")
                        hookDecryptFunction(test2, address);
                    }
                }
            }
        });
    }
}

var func_address = 'DECRYPT_FUNC_ADD'; 

hookCocosCreatorDecrypt(func_address)