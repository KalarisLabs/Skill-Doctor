const fs = require('fs');
const path = require('path');
const yaml = require('js-yaml');

const THREATS_DIR = path.join(__dirname, '../data/threats');
const OUTPUT_FILE = path.join(__dirname, '../data/threats.json');

function compile() {
  const files = fs.readdirSync(THREATS_DIR).filter(f => f.endsWith('.yaml'));
  const threats = [];

  for (const file of files) {
    const content = fs.readFileSync(path.join(THREATS_DIR, file), 'utf8');
    try {
      const doc = yaml.load(content);
      threats.push(doc);
    } catch (e) {
      console.error(`Error parsing ${file}:`, e.message);
    }
  }

  fs.writeFileSync(OUTPUT_FILE, JSON.stringify(threats, null, 2));
  console.log(`Compiled ${threats.length} threats to ${OUTPUT_FILE}`);
}

compile();
