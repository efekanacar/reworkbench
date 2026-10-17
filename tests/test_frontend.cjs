const assert = require('node:assert/strict');
const {formatSize,statusLabel,buildRows,tableDefs} = require('../reworkbench/web/app.js');
assert.equal(formatSize(0),'0 B');
assert.equal(formatSize(1024),'1.0 KiB');
assert.equal(formatSize(1048576),'1.00 MiB');
assert.equal(statusLabel('cancelled'),'İptal edildi');
assert.deepEqual(buildRows(tableDefs.strings,[{offset:16,encoding:'utf-8',text:'<script>untrusted</script>'}]),[['0x10','utf-8','<script>untrusted</script>']]);
assert.equal(buildRows(tableDefs.disassembly,[{address:'0x1000',mnemonic:'ret'}])[0][2],'ret');
console.log('Frontend format, label and table data tests passed.');
