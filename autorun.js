const { exec } = require("child_process");

// ganti node disini ya
const SCRIPT = "node hage GET https://journal.literasisains.id/ 600 32 128 msi.txt --cdn true --hver 2 --legit true --full";

const INTERVAL = 605;

function runScript() {
  console.log(`[${new Date().toLocaleString()}] Menjalankan script...`);
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

// jalanin sesuai dengan time yg diatas biar sesuai ( 600s aja recom )
setInterval(runScript, INTERVAL * 1000);
