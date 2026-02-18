const { exec } = require("child_process");

// ambil URL dari argument
const targetUrl = process.argv[2];

const SCRIPT = `node hage GET ${targetUrl} 600 32 128 msi.txt --cdn true --hver 2 --legit true --full`;

const INTERVAL = 605;

function runScript() {
  console.log(`[${new Date().toLocaleString()}] Menjalankan script ke ${targetUrl}`);
  exec(SCRIPT, (err, stdout, stderr) => {
    if (err) {
      console.error(`❌ Error: ${err.message}`);
      return;
    }
    if (stderr) console.error(`⚠️ Stderr: ${stderr}`);
    console.log(`✅ Output:\n${stdout}`);
  });
}

runScript();
setInterval(runScript, INTERVAL * 1000);
