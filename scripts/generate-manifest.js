const fs = require('fs');
const path = require('path');

try {
  const pkg = JSON.parse(fs.readFileSync('package.json', 'utf8'));
  const version = pkg.version;
  const nsisDir = path.join('src-tauri', 'target', 'release', 'bundle', 'nsis');
  console.log(nsisDir)
  if (!fs.existsSync(nsisDir)) {
    console.error(`Error: NSIS directory not found at ${nsisDir}`);
    process.exit(1);
  }

  const files = fs.readdirSync(nsisDir);
  const sigFile = files.find(f => f.endsWith('.exe.sig'));
  if (!sigFile) {
    console.error('Error: No .sig file found in NSIS directory!');
    process.exit(1);
  }

  const exeFile = sigFile.replace('.sig', '');
  const signature = fs.readFileSync(path.join(nsisDir, sigFile), 'utf8').trim();

  const manifest = {
    version: version,
    notes: `Kepler Release v${version}`,
    pub_date: new Date().toISOString(),
    platforms: {
      'windows-x86_64': {
        signature: signature,
        url: `https://github.com/sobdurated/kepler/releases/download/v${version}/${exeFile}`
      }
    }
  };

  const outputDir = path.join('src-tauri', 'target', 'release');
  if (!fs.existsSync(outputDir)) {
    fs.mkdirSync(outputDir, { recursive: true });
  }

  const outputPath = path.join(outputDir, 'latest.json');
  fs.writeFileSync(outputPath, JSON.stringify(manifest, null, 2));
  console.log(`Successfully generated latest.json at ${outputPath}`);
} catch (err) {
  console.error('Failed to generate latest.json:', err);
  process.exit(1);
}
